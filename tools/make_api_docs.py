#!/usr/bin/env python3
"""make_api_docs.py - write the generated parts of docs/API.md from the code.

  python3 tools/make_api_docs.py            rewrite docs/API.md
  python3 tools/make_api_docs.py --check    exit 1 if docs/API.md is out of date (what the test and CI run)

Standard library only. The Python tools are read with ast (their functions, docstrings and argparse options), the C header and the sketches as text, and the
secure-element configuration by running the project's own designer (tools/se_config.py) on the real chip's dump in docs/step1_bringup_output.txt, so every number
comes from the code or the evidence and none is typed in. Everything between <!-- api:NAME:start --> and <!-- api:NAME:end --> is replaced; the rest is written by hand.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "API.md"
PY_TOOLS = ["tools/se_config.py", "tools/se_pubkey.py", "tools/se_provision.py", "tools/se_verify_sig.py"]
C_HEADERS = ["firmware/se_lora_node/se_link.h"]
FACTORY_DUMP = "docs/step1_bringup_output.txt"


# ---------------------------------------------------------------- small helpers
def esc(s):
    return s.replace("|", "\\|")


def first_sentence(text):
    """The first sentence of a text (up to the first . ? or ! followed by a space or the end), or all of it."""
    m = re.search(r"[.?!](?=\s|$)", text)
    return text[:m.end()] if m else text


def first_paragraph(doc):
    return re.sub(r"\s+", " ", (doc or "").strip().split("\n\n")[0]).strip()


def strip_name(text):
    """Remove a leading 'path/name.ext - ' from a summary."""
    return re.sub(r"^[\w./-]+\s+-\s+", "", text)


def comment_text(lines):
    t = " ".join(lines)
    t = re.sub(r"/\*+|\*+/", " ", t)
    t = re.sub(r"(^|\s)\*+(?=\s|$)", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def top_comment(text):
    """The comment that opens a C or Arduino file, cleaned, without the leading 'name - ' (empty if the file does not open that way)."""
    t = text.lstrip()
    if not t.startswith("/*") or "*/" not in t:
        return ""
    body = comment_text(t[:t.index("*/") + 2].split("\n"))
    m = re.match(r"^[\w/.]+\s+-\s+(.*)$", body)
    return m.group(1) if m else ""


def parse_header(text):
    """Summary, #define constants and function/typedef declarations of a C header: a dict."""
    lines = text.split("\n")
    constants, functions = [], []
    for ln in lines:
        m = re.match(r"^#define[ \t]+([A-Za-z_]\w*)[ \t]+(.*)$", ln)
        if m:
            value, _, comment = m.group(2).partition("/*")
            if value.strip():
                constants.append((m.group(1), value.strip(), comment.replace("*/", "").strip()))
    i = 0
    while i < len(lines):
        ln = lines[i]
        is_td = re.match(r"^typedef\s+(?!struct\b|enum\b)", ln)
        is_fn = (not is_td) and re.match(r'^(?!#|/\*|\*|\}|extern\s+"C")[A-Za-z_][\w \t*]*?\b(\w+)\s*\(', ln)
        if is_td or is_fn:
            j = i
            while ";" not in lines[j]:
                j += 1
            decl = " ".join(x.strip() for x in lines[i:j + 1])
            decl = re.sub(r"\s+", " ", re.sub(r"/\*.*?\*/", "", decl).rstrip(";").strip())
            m = (re.search(r"\(\s*\*\s*(\w+)\s*\)", decl) if is_td else is_fn)
            comment = ""
            if i > 0 and lines[i - 1].rstrip().endswith("*/"):
                k = i - 1
                while "/*" not in lines[k]:
                    k -= 1
                comment = comment_text(lines[k:i])
            functions.append((m.group(1), decl, comment))
            i = j
        i += 1
    return {"summary": first_sentence(top_comment(text)), "constants": constants, "functions": functions}


def python_constants(rel):
    """Integer constants assigned at the top level of a Python file ({name: value}); simple arithmetic is evaluated, anything else is skipped."""
    ops = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b, ast.LShift: lambda a, b: a << b,
           ast.BitOr: lambda a, b: a | b, ast.RShift: lambda a, b: a >> b, ast.BitAnd: lambda a, b: a & b}

    def ev(node, env):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            return env[node.id]
        if isinstance(node, ast.BinOp):
            return ops[type(node.op)](ev(node.left, env), ev(node.right, env))
        raise ValueError(type(node).__name__)

    env = {}
    for node in ast.parse((ROOT / rel).read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                env[node.targets[0].id] = ev(node.value, env)
            except (ValueError, KeyError, TypeError):
                continue
    return env


def load_tool(name):
    """Import tools/<name>.py by path (the secure-element designer needs only the standard library)."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def public_functions(rel):
    """[(name, signature, docstring)] of the public top-level functions of a Python file."""
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
    return [(n.name, f"({ast.unparse(n.args)})", ast.get_docstring(n) or "") for n in tree.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")]


def argparse_rows(tree):
    rows = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
            names = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            kw = {k.arg: k.value for k in node.keywords}

            def lit(key):
                try:
                    return ast.literal_eval(kw[key]) if key in kw else None
                except ValueError:
                    return None
            extra = []
            if lit("required"):
                extra.append("required")
            if lit("default") is not None:
                extra.append(f"default `{lit('default')}`")
            rows.append((", ".join(f"`{n}`" for n in names), " ".join((lit("help") or "").split()), "; ".join(extra)))
    return rows


def atecc_copies():
    """{sketch folder: text of its atecc_io.h} for every sketch that carries its own copy."""
    return {p.parent.name: p.read_text(encoding="utf-8") for p in sorted((ROOT / "firmware").glob("*/atecc_io.h"))}


def atecc_functions(text):
    """{function name: its source text} for the inline functions of an atecc_io.h copy."""
    out = {}
    for m in re.finditer(r"^(?:static\s+)?inline\s+[\w\s\*]+?\b(\w+)\s*\([^)]*\)\s*\n?\{.*?^\}", text, re.S | re.M):
        out[m.group(1)] = m.group(0)
    return out


def sketch_dirs():
    return sorted(p for p in (ROOT / "firmware").iterdir() if p.is_dir())


def design():
    """(factory, image, changed byte offsets, se_config module) from the real chip's dump and this project's design."""
    se = load_tool("se_config")
    factory = se.parse_dump((ROOT / FACTORY_DUMP).read_text(encoding="utf-8"))
    image = se.apply_design(factory)
    return factory, image, [i for i in range(len(image)) if image[i] != factory[i]], se


# ---------------------------------------------------------------- the generated sections
def section_python():
    out = []
    for rel in PY_TOOLS:
        tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        out += [f"#### `{rel}`", "", first_sentence(strip_name(first_paragraph(ast.get_docstring(tree)))), ""]
        fns = public_functions(rel)
        out += ["| Function | Arguments | What it does |", "|---|---|---|"] + [f"| `{n}` | `{esc(s)}` | {esc(first_paragraph(d))} |" for n, s, d in fns] + [""]
        rows = argparse_rows(tree)
        if rows:
            out += ["Command line:", "", "| Option | What it does | Notes |", "|---|---|---|"] + [f"| {n} | {esc(h)} | {x} |" for n, h, x in rows] + [""]
    return "\n".join(out).rstrip("\n")


def section_constants():
    k = python_constants("tools/se_config.py")
    names = sorted((n for n in k if n.startswith("OFF_") or n == "CONFIG_SIZE"), key=lambda n: (k[n], n))
    out = ["| Name | Value | Meaning |", "|---|---|---|"]
    out += [f"| `{n}` | {k[n]} (`0x{k[n]:02X}`) | byte offset in the 128-byte configuration zone |" if n != "CONFIG_SIZE" else f"| `{n}` | {k[n]} | size of the configuration zone in bytes |" for n in names]
    return "\n".join(out)


def section_config():
    factory, image, changed, se = design()
    out = [f"The designer applied to the configuration zone that was read from the real chip (`{FACTORY_DUMP}`) changes **{len(changed)} byte{'s' if len(changed) != 1 else ''}**: "
           f"{', '.join(map(str, changed))}. Everything else stays as the chip had it. The lock CRC for the result is `0x{se.crc16(image)[0] | (se.crc16(image)[1] << 8):04X}`.", "",
           "| Slot | SlotConfig | KeyConfig | What it is | In words |", "|---|---|---|---|---|"]
    for slot in sorted(set(se.DESIGN) | {se.IDENTITY_SLOT}):
        what = se.PURPOSE.get(slot, "") + ("" if slot in se.DESIGN else " (factory setting, not changed by the design)")
        out.append(f"| {slot} | `0x{se.slot_config(image, slot):04X}` | `0x{se.key_config(image, slot):04X}` | {esc(what.strip())} | {esc(se.describe_slot(image, slot))} |")
    return "\n".join(out)


def section_c():
    out = []
    for rel in C_HEADERS:
        info = parse_header((ROOT / rel).read_text(encoding="utf-8"))
        out += [f"#### `{rel}`", "", info["summary"], ""]
        out += ["| Name | Declaration | What it does |", "|---|---|---|"] + [f"| `{n}` | `{esc(d)}` | {esc(c)} |" for n, d, c in info["functions"]] + [""]
        out += ["| Constant | Value | Meaning |", "|---|---|---|"] + [f"| `{n}` | `{esc(v)}` | {esc(c)} |" for n, v, c in info["constants"]]
    return "\n".join(out)


def section_atecc():
    copies = atecc_copies()
    funcs = {k: atecc_functions(v) for k, v in copies.items()}
    names = sorted({n for f in funcs.values() for n in f})
    folders = list(copies)
    out = ["| Copy in | Lines | SHA-256 (first 8) |", "|---|---|---|"]
    out += [f"| `firmware/{k}/atecc_io.h` | {len(copies[k].splitlines())} | `{hashlib.sha256(copies[k].encode()).hexdigest()[:8]}` |" for k in folders]
    out += ["", "| Function | " + " | ".join(f"`{k}`" for k in folders) + " |", "|---|" + "---|" * len(folders)]
    out += [f"| `{n}` | " + " | ".join("yes" if n in funcs[k] else "" for k in folders) + " |" for n in names]
    return "\n".join(out)


def section_sketches():
    out = ["| Folder | What it does | Other files |", "|---|---|---|"]
    for d in sketch_dirs():
        ino = next(d.glob("*.ino"))
        others = ", ".join(f"`{p.name}`" for p in sorted(d.iterdir()) if p != ino)
        out.append(f"| `firmware/{d.name}/` | {esc(first_sentence(top_comment(ino.read_text(encoding='utf-8'))))} | {others} |")
    return "\n".join(out)


def test_files():
    return sorted(p.name for p in (ROOT / "tools").glob("test_*.py"))


def section_tests():
    out = ["| Program | What it checks |", "|---|---|"]
    for name in test_files():
        doc = ast.get_docstring(ast.parse((ROOT / "tools" / name).read_text(encoding="utf-8")))
        out.append(f"| `tools/{name}` | {esc(first_sentence(strip_name(first_paragraph(doc))))} |")
    text = (ROOT / "tools" / "crosscheck" / "crosscheck.c").read_text(encoding="utf-8")
    out.append(f"| `tools/crosscheck/crosscheck.c` | {esc(first_sentence(top_comment(text)))} |")
    return "\n".join(out)


def section_doctests():
    tree = ast.parse((ROOT / "tools" / "test_docs.py").read_text(encoding="utf-8"))
    tests = sorted((n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")), key=lambda n: n.lineno)
    return "\n".join(f"- {first_paragraph(ast.get_docstring(n))}" for n in tests)


SECTIONS = {"python": section_python, "constants": section_constants, "config": section_config, "c": section_c, "atecc": section_atecc, "sketches": section_sketches,
            "tests": section_tests, "doctests": section_doctests}


def fill(doc):
    """docs/API.md with every generated section rewritten. Raises SystemExit if a marker is missing."""
    for name, fn in SECTIONS.items():
        start, end = f"<!-- api:{name}:start -->", f"<!-- api:{name}:end -->"
        if start not in doc or end not in doc:
            sys.exit(f"make_api_docs: {DOC} has no '{start}' ... '{end}' markers")
        a, b = doc.index(start) + len(start), doc.index(end)
        doc = doc[:a] + "\n" + fn() + "\n" + doc[b:]
    return doc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 if docs/API.md is out of date")
    a = ap.parse_args(argv)
    current = DOC.read_text(encoding="utf-8").replace("\r\n", "\n")
    new = fill(current)
    if a.check:
        if new != current:
            print("docs/API.md is out of date: run  python3 tools/make_api_docs.py", file=sys.stderr)
            return 1
        print("docs/API.md is up to date")
        return 0
    if new == current:
        print("docs/API.md already up to date")
    else:
        DOC.write_text(new, encoding="utf-8", newline="\n")
        print("docs/API.md updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
