#!/usr/bin/env python3
"""tools/test_docs.py - keeps docs/API.md, the README and the other documents honest: every number they repeat is checked against the code or the evidence it comes from.

    python3 -m unittest discover -s tools -v

Standard library only (plus gcc, and the 'cryptography' package for the tests that already need it). The cross-check test needs the STM32 project next to this repository.
"""
import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import make_api_docs as gen  # noqa: E402

STM32_FILES = {"aes128.c", "aes_cmac.c", "secure_link.c", "secure_link.h", "secure_link_keys.h", "fcnt_store.c", "fcnt_store.h"}
STM32_FOLDERS = {"feather_receiver/", "secure_link/"}
DOCS = ["README.md", "SECURITY.md", "docs/API.md", "docs/CRA_MAPPING.md", "docs/THREAT_MODEL.md"]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def run(cmd, cwd=ROOT, **kw):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, **kw)


def readme_section(title):
    text = read("README.md")
    a = text.index(f"## {title}")
    nxt = text.find("\n## ", a + 3)
    return text[a:nxt if nxt != -1 else len(text)]


def stm32_secure_link():
    p = os.environ.get("STM32_SL") or str(ROOT.parent / "stm32l0-freertos-sensor-node" / "secure_link")
    return Path(p) if Path(p, "secure_link.c").is_file() else None


class Numbers(unittest.TestCase):
    """The numbers the README and the documents repeat must be the numbers in the code and the evidence."""

    @classmethod
    def setUpClass(cls):
        cls.factory, cls.image, cls.changed, cls.se = gen.design()

    def test_the_readme_slot_table_matches_the_design(self):
        """The README's secure-element layout table gives the same SlotConfig and KeyConfig for slot 0 and slot 10 as the designer produces."""
        rows = {int(m.group(1)): (int(m.group(2), 16), int(m.group(3), 16))
                for m in re.finditer(r"^\| (\d+) \|.*SlotConfig `0x([0-9A-Fa-f]{4})`.*KeyConfig `0x([0-9A-Fa-f]{4})`", readme_section("Secure element layout"), re.M)}
        self.assertEqual(set(rows), {0, 10}, "the README's layout table has changed shape")
        for slot, (sc, kc) in rows.items():
            self.assertEqual((self.se.slot_config(self.image, slot), self.se.key_config(self.image, slot)), (sc, kc), f"slot {slot}")

    def test_the_readme_says_which_configuration_bytes_changed_and_how_many(self):
        """The 'three configuration bytes were changed (40, 41, 116)' sentence and the measurements row 'Configuration bytes changed | 3' equal what the designer changes in the real chip's dump."""
        text = read("README.md")
        m = re.search(r"changed from the factory values \(([\d, ]+)\)", text)
        self.assertIsNotNone(m, "the README sentence about the changed configuration bytes has changed shape")
        self.assertEqual([int(x) for x in m.group(1).split(",")], self.changed)
        row = re.search(r"\| Configuration bytes changed from factory \| (\d+) \|", text)
        self.assertEqual(int(row.group(1)), len(self.changed))
        self.assertIn(f"Only {['zero', 'one', 'two', 'three', 'four', 'five'][len(self.changed)]} configuration bytes", text)

    def test_every_committed_copy_of_the_configuration_header_is_what_the_designer_writes(self):
        """firmware/se_config_image.h and the copy in every sketch that includes it are exactly the header that tools/se_config.py writes for the real chip's dump."""
        expected = self.se.c_header(self.image)
        wanted = {d.name for d in gen.sketch_dirs() if any('#include "se_config_image.h"' in f.read_text(encoding="utf-8") for f in d.glob("*.ino"))}
        have = {p.parent.name for p in (ROOT / "firmware").glob("*/se_config_image.h")}
        self.assertEqual(have, wanted, "a sketch that includes se_config_image.h lacks its copy (Arduino needs it in the sketch folder), or a stray copy exists")
        copies = [ROOT / "firmware" / "se_config_image.h"] + [ROOT / "firmware" / d / "se_config_image.h" for d in sorted(wanted)]
        for p in copies:
            self.assertEqual(p.read_text(encoding="utf-8").replace("\r\n", "\n").rstrip("\n"), expected.rstrip("\n"), f"{p.relative_to(ROOT)} differs from the designer's output")

    def test_the_measured_times_in_the_readme_are_the_ones_in_the_logged_output(self):
        """The README's identity-key time and per-packet sealing time equal what the logged Serial Monitor output of the board shows (every logged seal time is the same value)."""
        text = read("README.md")
        key = re.search(r"\| Identity key generation \(GenKey inside the chip\) \| (\d+) ms \|", text)
        logged = re.search(r"in (\d+) ms", read("docs/step5_identity_key_output.txt"))
        self.assertEqual(key.group(1), logged.group(1))
        seal = re.search(r"\| Sealing one packet .*? \| ([\d.]+) ms \|", text)
        times = set(re.findall(r"seal=([\d.]+) ms", read("docs/step7_mkr_output.txt")))
        self.assertEqual(times, {seal.group(1)}, f"the logged seal times are {sorted(times)}, the README says {seal.group(1)}")
        diagram = re.search(r"diagram:mkr_components -->(.*?)\*The keys never leave", text, re.S).group(1)
        self.assertIn(f"per short packet, {seal.group(1)} ms", diagram, "the diagram quotes a different sealing time from the table")

    def test_the_packet_count_in_every_document_is_the_crosscheck_count(self):
        """Every '2,000 packets' in the README, the CRA mapping and the threat model equals the number of cases the cross-check program runs."""
        cases = int(re.search(r"cases = (\d+)", read("tools/crosscheck/crosscheck.c")).group(1))
        for doc in ["README.md", "docs/CRA_MAPPING.md", "docs/THREAT_MODEL.md"]:
            found = [int(x.replace(",", "")) for x in re.findall(r"(\d[\d,]*)(?:,? 0 differences| (?:random )?packets)", read(doc))]
            self.assertTrue(found, f"{doc} no longer states the cross-checked packet count")
            self.assertEqual(set(found), {cases}, f"{doc}: {found} against {cases} in crosscheck.c")

    def test_the_threat_count_in_the_readme_is_the_number_of_threats_in_the_threat_model(self):
        """The README's '12 threats' equals the number of distinct SE-nn threat rows in docs/THREAT_MODEL.md."""
        stated = int(re.search(r"(\d+) threats", read("README.md")).group(1))
        rows = set(re.findall(r"^\| (SE-\d+) \|", read("docs/THREAT_MODEL.md"), re.M))
        self.assertEqual(stated, len(rows))

    def test_the_counter_limit_and_its_duration_are_consistent(self):
        """The hardware counter limit in the README is 2^21 - 1, and at one packet per 15 s that really is about a year."""
        text = read("README.md")
        limit = int(re.search(r"counter stops at ([\d,]+)", text).group(1).replace(",", ""))
        self.assertEqual(limit, 2 ** 21 - 1)
        claims = re.findall(r"about ([\w ]+?) at one packet per (\d+) s", text)
        self.assertTrue(claims, "the README no longer says how long the counter lasts")
        for words, seconds in claims:                               # every place that says it
            self.assertEqual(words, "a year", f"the README says the counter lasts '{words}'")
            self.assertTrue(350 < limit * int(seconds) / 86400 < 380, f"{limit} packets at {seconds} s each is no longer about a year")

    def test_the_packet_format_in_the_readme_and_in_se_link_h_is_the_same_and_adds_up(self):
        """README, se_link.h's comment and its constants all describe a 1-byte id, 4-byte counter and 4-byte MIC, and the CTR block layout adds up to 16 bytes."""
        header = read("firmware/se_lora_node/se_link.h")
        for name, text in (("README.md", read("README.md")), ("se_link.h", header)):
            self.assertEqual(re.search(r"\[dev_id (\d)B\]\[fcnt (\d)B", text).groups(), ("1", "4"), name)
            self.assertEqual(re.search(r"MIC (\d)B\]", text).group(1), "4", name)
        k = {n: v for n, v, _ in gen.parse_header(header)["constants"]}
        self.assertEqual((k["SE_HDR_LEN"], k["SE_MIC_LEN"]), ("5U", "4U"))
        ctr = re.search(r"CTR (?:counter )?block:\s+(\w\w) \| dev_id \| fcnt \(LE(?:, 4B)?\) \| 00 x(\d) \| block index", read("README.md"))
        self.assertEqual(1 + 1 + 4 + int(ctr.group(2)) + 1, 16)


class Documentation(unittest.TestCase):
    """docs/API.md, the README and the code."""

    def test_the_generated_parts_of_api_md_are_current(self):
        """The tables in docs/API.md are exactly what tools/make_api_docs.py writes from the code and the evidence today."""
        r = run([sys.executable, "tools/make_api_docs.py", "--check"])
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)

    def test_every_public_function_in_the_python_tools_has_a_docstring(self):
        """Every public function of the four Python tools has a docstring, so the generated reference has no blank descriptions."""
        for rel in gen.PY_TOOLS:
            for name, _, doc in gen.public_functions(rel):
                self.assertTrue(doc.strip(), f"{rel}: {name} has no docstring")

    def test_every_option_of_the_python_tools_has_help_text(self):
        """Every command-line option of the Python tools has help text."""
        for rel in gen.PY_TOOLS:
            for names, help_text, _ in gen.argparse_rows(ast.parse(read(rel))):
                self.assertTrue(help_text, f"{rel}: option {names} has no help text")

    def test_every_tool_and_every_sketch_is_in_the_reference(self):
        """Every Python file in tools/ is a documented tool, a test, or the generator itself, and every folder in firmware/ has an entry in the sketch table."""
        allowed = {Path(p).name for p in gen.PY_TOOLS} | {"make_api_docs.py"} | set(gen.test_files())
        self.assertEqual({p.name for p in (ROOT / "tools").glob("*.py")} - allowed, set(), "a tool was added without adding it to tools/make_api_docs.py")
        api = read("docs/API.md")
        for d in gen.sketch_dirs():
            self.assertIn(f"`firmware/{d.name}/`", api)
            self.assertTrue(gen.top_comment(next(d.glob("*.ino")).read_text(encoding="utf-8")), f"{d.name}: the sketch should open with '/* name.ino - summary'")

    def test_the_c_header_is_fully_listed(self):
        """A second, simpler reading of se_link.h finds the same functions and #define constants as appear in the generated C tables."""
        text = read("firmware/se_lora_node/se_link.h")
        api = read("docs/API.md")
        for name in re.findall(r"^#define[ \t]+(\w+)[ \t]+\S", text, re.M) + [m.group(1) for m in re.finditer(r"^int (\w+)\(", text, re.M)] + ["se_aes_fn"]:
            if name != "SE_LINK_H":
                self.assertIn(f"`{name}`", api)
        for ln in text.split("\n"):
            if re.match(r"^(int|typedef)\b", ln):
                self.assertTrue(gen.parse_header(text)["functions"])

    def test_the_readme_repository_layout_and_commands_match_the_files(self):
        """Every folder and tool in the README's repository layout exists, every sketch folder and tool file is in it, and every test file has a command in 'Build and test'."""
        layout = re.search(r"```\n(firmware/.*?)```", readme_section("Repository layout"), re.S).group(1)
        listed_fw = set(re.findall(r"^  (se_\w+)/", layout, re.M))
        self.assertEqual(listed_fw, {d.name for d in gen.sketch_dirs()})
        listed_tools = set(re.findall(r"\b((?:se_|test_)\w+\.py)", layout))
        for t in listed_tools:
            self.assertTrue((ROOT / "tools" / t).is_file(), f"README lists tools/{t}")
        self.assertEqual(listed_tools, {p.name for p in (ROOT / "tools").glob("*.py")} - {"make_api_docs.py", "test_docs.py"})
        self.assertTrue((ROOT / "tools" / "crosscheck").is_dir())
        build = readme_section("Build and test")
        commands = set(re.findall(r"python3 tools/(test_\w+\.py)", build))
        self.assertEqual(commands, {n for n in gen.test_files() if n != "test_docs.py"})

    def test_every_file_path_mentioned_in_the_documents_exists(self):
        """Every file or folder named in backticks in the README and the documents exists in the repository (the git-ignored secrets folder and build outputs excepted); the STM32 project's files are looked for in that project when it is next to this one."""
        paths = set()
        for dirpath, dirnames, files in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            rel = Path(dirpath).relative_to(ROOT).as_posix()
            paths.add("" if rel == "." else rel)
            paths.update((Path(rel) / f).as_posix() if rel != "." else f for f in files)
        missing = []
        for doc in DOCS:
            for tok in set(re.findall(r"`([^`\n]+)`", read(doc))):
                tok = tok.strip()
                if not (re.fullmatch(r"[\w./-]+\.(c|h|py|sh|md|ino|txt|pem|yml)", tok) or re.fullmatch(r"[\w-]+/[\w./-]*", tok)):
                    continue
                if tok.startswith(("keys/", "../")) or tok.endswith("se_provision_data.h") or "<" in tok or "*" in tok:
                    continue
                if tok in STM32_FILES or tok in STM32_FOLDERS:          # belongs to the STM32 project, not to this repository
                    sl = stm32_secure_link()
                    if sl is not None and tok != "secure_link_keys.h":
                        found = (sl.parent / tok).is_dir() if tok in STM32_FOLDERS else (sl / tok).is_file()
                        self.assertTrue(found, f"{doc} names {tok}, which is not in the STM32 project")
                    continue
                t = tok.rstrip("/")
                if not (t in paths or any(p.endswith("/" + t) for p in paths) or any(p.startswith(t + "/") for p in paths)):
                    missing.append(f"{doc}: {tok}")
        self.assertEqual(missing, [])

    def test_the_examples_in_api_md_run(self):
        """The Python example in API.md runs, and the C example compiles with warnings as errors, links with the real se_link.c and returns the packet length 12."""
        api = read("docs/API.md")
        py = re.search(r"<!-- example-python:start -->\s*```python\n(.*?)```", api, re.S).group(1)
        r = run([sys.executable, "-c", py])
        self.assertEqual(r.returncode, 0, r.stderr)
        c = re.search(r"<!-- example-c:start -->\s*```c\n(.*?)```", api, re.S).group(1)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "ex.c").write_text(c + "\nint main(void) { return seal_three_bytes() == 12 ? 0 : 1; }\n", encoding="utf-8")
            r = run(["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I", "firmware/se_lora_node", "-o", str(Path(d) / "ex"), str(Path(d) / "ex.c"), "firmware/se_lora_node/se_link.c"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(run([str(Path(d) / "ex")]).returncode, 0, "seal_three_bytes() did not return 12 (= SE_HDR_LEN + 3 + SE_MIC_LEN)")


class Copies(unittest.TestCase):
    """Files that exist in more than one place."""

    def test_the_two_newest_chip_command_layers_are_identical_and_the_older_ones_share_the_same_functions(self):
        """atecc_io.h in se_lora_node and se_provision are identical; in the older sketches every function that also exists in the newest copy is the same text, except receive and receiveStatus."""
        copies = gen.atecc_copies()
        self.assertEqual(copies["se_lora_node"], copies["se_provision"], "the newest two copies of atecc_io.h have diverged")
        newest = gen.atecc_functions(copies["se_lora_node"])
        self.assertIn("crc16", newest)
        for folder, text in copies.items():
            for name, body in gen.atecc_functions(text).items():
                if name in newest and name not in ("receive", "receiveStatus"):
                    self.assertEqual(body, newest[name], f"firmware/{folder}/atecc_io.h: {name} differs from the newest copy")

    @unittest.skipIf(stm32_secure_link() is None, "the STM32 project is not next to this repository (set STM32_SL to its secure_link/ folder): the cross-check was skipped")
    def test_the_two_secure_link_implementations_agree(self):
        """The packet code that runs on the MKR builds packets byte-identical to the STM32 project's secure_link.c, and the receiver's sl_open accepts them (the cross-check program)."""
        d = ROOT / "tools" / "crosscheck"
        try:
            r = run(["make", f"STM32_SL={stm32_secure_link()}"], cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr[-800:])
            out = run(["./crosscheck"], cwd=d)
        finally:
            run(["make", "clean"], cwd=d)
        self.assertEqual(out.returncode, 0, out.stdout[-500:])
        cases = int(re.search(r"cases = (\d+)", read("tools/crosscheck/crosscheck.c")).group(1))
        self.assertIn(f"ALL MATCH: {cases} random packets, 0 failure(s)", out.stdout)


class Wiring(unittest.TestCase):
    """CI and housekeeping."""

    def test_ci_runs_the_tests_with_the_stm32_project_checked_out_beside_this_one(self):
        """The CI workflow installs cryptography, checks out both repositories side by side, runs every test with 'unittest discover -s tools', and triggers on push to main and on pull requests."""
        ci = read(".github/workflows/ci.yml")
        self.assertIn("pip install cryptography", ci)
        self.assertIn("python -m unittest discover -s tools", ci)
        self.assertIn("repository: baliyu/stm32l0-freertos-sensor-node", ci)
        self.assertIn("path: mkrwan-secure-element-node", ci)
        self.assertIn("path: stm32l0-freertos-sensor-node", ci)
        self.assertRegex(ci, r"(?m)^  pull_request:")
        self.assertRegex(ci, r"(?m)^  push:")

    def test_python_bytecode_and_the_crosscheck_program_are_ignored_and_no_bytecode_is_committed(self):
        """.gitignore ignores __pycache__ and the built cross-check program, and git tracks no bytecode file."""
        ign = read(".gitignore")
        self.assertIn("__pycache__/", ign)
        self.assertIn("tools/crosscheck/crosscheck", ign)
        r = run(["git", "ls-files"])
        if r.returncode == 0:
            tracked = [f for f in r.stdout.split("\n") if f and (ROOT / f).exists()]       # a file deleted from disk but not yet from the index is on its way out
            self.assertEqual([f for f in tracked if f.endswith(".pyc") or "__pycache__" in f], [])


if __name__ == "__main__":
    unittest.main()
