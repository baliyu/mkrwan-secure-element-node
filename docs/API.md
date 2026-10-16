# Interfaces

What other code, or a person, can depend on in this repository: the Python tools, the C packet-building code that runs on the MKR WAN 1310, the Arduino sketches (one per
step), the secure-element configuration they all share, and the tests. The design and the security reasoning are in the [README](../README.md) and in
[THREAT_MODEL.md](THREAT_MODEL.md); they are not repeated here.

The tables below are **generated** from the code and the evidence files by `python3 tools/make_api_docs.py` (between the `api:` markers; do not edit them by hand), and
`tools/test_docs.py` fails if they fall behind. The same test checks the numbers that the README and the other documents repeat (slot settings, the bytes changed from the
factory configuration, the measured times, the 2,000 cross-checked packets, the counter limit) against the code or the evidence they come from.

Not covered here: the Arduino sketches' behaviour on the chip (it needs the board; the Serial Monitor output of every step is kept in `docs/`), and the LoRa radio code.

## 1. How the pieces fit

The secure element (an ATECC608) is set up once, in steps that cannot be undone, and then used by the LoRa node. Each step has a sketch in `firmware/` and, where the PC
takes part, a tool in `tools/`:

1. **Bring-up** (`se_bringup`): read the chip's configuration without changing anything.
2. **Design** (`tools/se_config.py`, PC only): turn that dump into the configuration this project wants, check it against safety rules and compute the CRC that the lock needs.
3. **Write configuration** (`se_write_config`): write the reviewed configuration and read it back. Does not lock.
4. **Lock configuration** (`se_lock_config`): permanent; asks for a typed confirmation.
5. **Identity key** (`se_identity_key`, then `tools/se_pubkey.py`): the chip creates a private key inside itself; only the public key leaves.
6. **Provision** (`tools/se_provision.py`, then `se_provision`): load the two link keys into slot 10, lock the data zone (permanent), and prove both keys work with known answers.
   (`se_aes_test` is the earlier test of the AES engine with published test keys.)
7. **LoRa node** (`se_lora_node`): build each packet's CTR encryption and CMAC from single AES blocks that the chip computes.

## 2. The secure-element configuration

<!-- api:config:start -->
The designer applied to the configuration zone that was read from the real chip (`docs/step1_bringup_output.txt`) changes **3 bytes**: 40, 41, 116. Everything else stays as the chip had it. The lock CRC for the result is `0x67BF`.

| Slot | SlotConfig | KeyConfig | What it is | In words |
|---|---|---|---|---|
| 0 | `0x2083` | `0x0033` | Device identity private key (generated inside, never readable) (factory setting, not changed by the design) | slot  0  SlotConfig=0x2083 KeyConfig=0x0033  P-256 ECC key; private; uses: ext-sign, int-sign; NEVER readable; writes after data lock: never; slot-lockable |
| 10 | `0x208F` | `0x0018` | LoRa link keys (AES-128): block 0 = encryption key, block 1 = MIC key | slot 10  SlotConfig=0x208F KeyConfig=0x0018  AES-128 key; NEVER readable; writes after data lock: never |
<!-- api:config:end -->

Byte offsets used by the designer (from `tools/se_config.py`):

<!-- api:constants:start -->
| Name | Value | Meaning |
|---|---|---|
| `OFF_AES_ENABLE` | 13 (`0x0D`) | byte offset in the 128-byte configuration zone |
| `OFF_I2C_ENABLE` | 14 (`0x0E`) | byte offset in the 128-byte configuration zone |
| `OFF_I2C_ADDRESS` | 16 (`0x10`) | byte offset in the 128-byte configuration zone |
| `OFF_SLOT_CONFIG` | 20 (`0x14`) | byte offset in the 128-byte configuration zone |
| `OFF_USER_EXTRA` | 84 (`0x54`) | byte offset in the 128-byte configuration zone |
| `OFF_LOCK_VALUE` | 86 (`0x56`) | byte offset in the 128-byte configuration zone |
| `OFF_LOCK_CONFIG` | 87 (`0x57`) | byte offset in the 128-byte configuration zone |
| `OFF_SLOT_LOCKED` | 88 (`0x58`) | byte offset in the 128-byte configuration zone |
| `OFF_KEY_CONFIG` | 96 (`0x60`) | byte offset in the 128-byte configuration zone |
| `CONFIG_SIZE` | 128 | size of the configuration zone in bytes |
<!-- api:constants:end -->

## 3. Python tools

Run them from the repository root. They need `pip install cryptography` (except the configuration designer, which needs only the standard library).

<!-- api:python:start -->
#### `tools/se_config.py`

ATECC608 configuration designer (step 2, PC only).

| Function | Arguments | What it does |
|---|---|---|
| `crc16` | `(data)` | ATECC CRC-16 (poly 0x8005, LSB-first), same as CryptoAuthLib atCRC. Returns the two bytes in the order the chip uses (little-endian). |
| `parse_dump` | `(text)` | Extract the 128 config bytes from se_bringup's Serial Monitor output. |
| `get16` | `(cfg, off)` | Read the little-endian 16-bit number at byte offset off of a configuration. |
| `put16` | `(cfg, off, value)` | Write value as a little-endian 16-bit number at byte offset off. |
| `slot_config` | `(cfg, slot)` | The 16-bit SlotConfig of a slot. |
| `key_config` | `(cfg, slot)` | The 16-bit KeyConfig of a slot. |
| `key_type` | `(kc)` | The 3-bit KeyType field of a KeyConfig value. |
| `apply_design` | `(factory)` | The 128-byte factory configuration with this project's SlotConfig and KeyConfig written into the designed slots; every other byte stays as the chip had it. Raises ValueError unless factory is 128 bytes. |
| `check` | `(image, factory)` | Safety rules. Returns a list of problems (empty = OK). |
| `describe_slot` | `(cfg, slot)` | One line in words saying what a slot's configuration allows. |
| `report` | `(image, factory)` | Text report of the design: the device identifiers, then every slot explained in words. |
| `c_header` | `(image)` | The text of the C header holding the 128-byte image and the CRC that the Lock command must be given. |
| `main` | `(argv=None)` | Command line: read the dump, apply the design, check it, print the report and optionally write the header. Returns 0 if every safety check passed, 1 if the design was rejected. |

Command line:

| Option | What it does | Notes |
|---|---|---|
| `dump` | Serial Monitor output from se_bringup |  |
| `--header` | write the C header with the image and lock CRC |  |

#### `tools/se_pubkey.py`

step 5 (PC side): check and save the device identity public key that the ATECC608 exported.

| Function | Arguments | What it does |
|---|---|---|
| `parse_pubkey` | `(text)` | The 64 raw bytes (X then Y) of the single 'PUBKEY:' line in the Serial Monitor text; ValueError if there is none, several different ones, or the wrong length. |
| `to_public_key` | `(raw)` | Raises ValueError if (X, Y) is not a point on P-256. |
| `fingerprint` | `(raw)` | The first 16 hex characters of the SHA-256 of the raw public key, to quote in the README. |
| `main` | `(argv=None)` | Command line: check the exported public key and save it as a PEM file with its fingerprint. |

Command line:

| Option | What it does | Notes |
|---|---|---|
| `output` | saved Serial Monitor output of se_identity_key |  |
| `--pem` | where to write the PEM (default docs/device_identity_pub.pem) |  |

#### `tools/se_provision.py`

step 6b (PC side): build the provisioning header that firmware/se_provision uses to load the LoRa link keys into slot 10.

| Function | Arguments | What it does |
|---|---|---|
| `parse_keys` | `(text)` | The two 16-byte link keys (SL_ENC_KEY and SL_MIC_KEY) read from the text of a C header; ValueError if one is missing or malformed. |
| `aes_ecb` | `(key, block)` | One AES-128 block encrypted in ECB mode; used only to compute the known-answer values. |
| `c_bytes` | `(b, indent='  ')` | The bytes as rows of 16 comma-separated C hex literals. |
| `build_header` | `(enc, mic, pubkey)` | The text of the secret provisioning header: the two link keys plus known answers computed on the PC for the chip to be checked against. |
| `main` | `(argv=None)` | Command line: build the provisioning header from the link keys. |

Command line:

| Option | What it does | Notes |
|---|---|---|
| `keys_header` | C header holding SL_ENC_KEY[16] and SL_MIC_KEY[16] (the secret keys/secure_link_keys.h) |  |
| `step5_output` | saved Serial Monitor output of se_identity_key (its PUBKEY line) |  |
| `--out` | where to write the provisioning header (secret, git-ignored) |  |

#### `tools/se_verify_sig.py`

step 6c (PC side): verify the ECDSA signature the ATECC608 made with its identity key (slot 0), using the public key saved in step 5.

| Function | Arguments | What it does |
|---|---|---|
| `parse` | `(text)` | The 32-byte signed message and the 64-byte signature from the Serial Monitor text (exactly one SIGN_MSG line and one SIGNATURE line). |
| `verify` | `(pub, msg, sig)` | True if sig (r then s, 32 bytes each) is a valid ECDSA P-256 signature of the already-hashed message msg under the public key pub. |
| `main` | `(argv=None)` | Command line: verify the chip's signature against the saved identity public key. |

Command line:

| Option | What it does | Notes |
|---|---|---|
| `output` | saved Serial Monitor output with the SIGN_MSG and SIGNATURE lines |  |
| `pem` | the saved identity public key (PEM), e.g. docs/device_identity_pub.pem |  |
<!-- api:python:end -->

### 3.1 Example

This is run by `tools/test_docs.py`. It applies the design to the dump read from the real chip, as step 2 does:

<!-- example-python:start -->
```python
import sys
sys.path.insert(0, "tools")
import se_config as se

factory = se.parse_dump(open("docs/step1_bringup_output.txt").read())   # what the chip held before step 3
image = se.apply_design(factory)                                        # with this project's design written in
assert se.check(image, factory) == []                                   # every safety rule passes
assert (se.slot_config(image, 10), se.key_config(image, 10)) == (0x208F, 0x0018)   # the link-key slot: AES key, never readable
```
<!-- example-python:end -->

## 4. C interface (the packet code that runs on the MKR)

<!-- api:c:start -->
#### `firmware/se_lora_node/se_link.h`

the secure_link packet format from the STM32 project, with every AES block computed by a caller-supplied function.

| Name | Declaration | What it does |
|---|---|---|
| `se_aes_fn` | `typedef int (*se_aes_fn)(void *ctx, uint8_t key_block, const uint8_t in[16], uint8_t out[16])` | One AES-128 block encryption with key block 'key_block'. Return 0 on success. |
| `se_cmac` | `int se_cmac(se_aes_fn aes, void *ctx, uint8_t key_block, const uint8_t *msg, size_t len, uint8_t tag[16])` | RFC 4493 AES-CMAC with key block 'key_block'. Returns 0 or SE_ERR_AES. |
| `se_seal` | `int se_seal(se_aes_fn aes, void *ctx, uint8_t dev_id, uint32_t fcnt, const uint8_t *payload, uint8_t len, uint8_t *out, uint8_t out_max)` | Build a packet. Returns its length, SE_ERR_LENGTH or SE_ERR_AES. |

| Constant | Value | Meaning |
|---|---|---|
| `SE_HDR_LEN` | `5U` |  |
| `SE_MIC_LEN` | `4U` |  |
| `SE_MAX_PAYLOAD` | `48U` |  |
| `SE_MAX_PACKET` | `(SE_HDR_LEN + SE_MAX_PAYLOAD + SE_MIC_LEN)` |  |
| `SE_KEY_ENC` | `0U` | AES key block 0 |
| `SE_KEY_MIC` | `1U` | AES key block 1 |
| `SE_ERR_LENGTH` | `(-1)` |  |
| `SE_ERR_AES` | `(-4)` | the AES function reported a failure |
<!-- api:c:end -->

### 4.1 Example

This is compiled and run by `tools/test_docs.py` with a stand-in for the chip (a real run asks the ATECC608 for each AES block):

<!-- example-c:start -->
```c
#include <stdint.h>
#include "se_link.h"

/* A stand-in for the chip: any function with this shape works. */
static int toy_aes(void *ctx, uint8_t key_block, const uint8_t in[16], uint8_t out[16])
{
  int i;
  (void)ctx;
  for (i = 0; i < 16; i++) out[i] = (uint8_t)(in[i] ^ key_block ^ 0x5A);
  return 0;
}

int seal_three_bytes(void)
{
  const uint8_t reading[3] = { 1, 2, 3 };
  uint8_t packet[SE_MAX_PACKET];
  return se_seal(toy_aes, 0, 7, 1, reading, sizeof reading, packet, sizeof packet);   /* 12 = 5 + 3 + 4 */
}
```
<!-- example-c:end -->

## 5. The Arduino sketches

<!-- api:sketches:start -->
| Folder | What it does | Other files |
|---|---|---|
| `firmware/se_aes_test/` | secure element project, step 6a: first test of the ATECC608's AES engine, with PUBLISHED TEST KEYS only (nothing secret). | `atecc_io.h`, `se_config_image.h` |
| `firmware/se_bringup/` | secure element project, step 1: READ-ONLY bring-up. |  |
| `firmware/se_identity_key/` | secure element project, step 5: create the device identity key INSIDE the ATECC608 and export its public key. | `se_config_image.h` |
| `firmware/se_lock_config/` | secure element project, step 4: LOCK the configuration zone of the ATECC608. | `atecc_io.h`, `se_config_image.h` |
| `firmware/se_lora_node/` | secure element project, step 7: LoRa sensor node whose link keys live in the ATECC608 and never leave it. | `atecc_io.h`, `se_link.c`, `se_link.h`, `se_node_config.h` |
| `firmware/se_provision/` | secure element project, step 6: load the LoRa link keys into slot 10, LOCK THE DATA ZONE (PERMANENT), then prove both keys work. | `atecc_io.h`, `se_config_image.h` |
| `firmware/se_write_config/` | secure element project, step 3: write the reviewed configuration to the ATECC608, read it back and compare. | `se_config_image.h` |
<!-- api:sketches:end -->

### 5.1 The chip command layer, `atecc_io.h`

Arduino only compiles files inside the sketch folder, so each sketch that talks to the chip directly carries its own copy of `atecc_io.h`. They are **different versions on
purpose**: each sketch was run on the board with the version it holds, and its Serial Monitor output in `docs/` was produced by that version. The newest two
(`se_lora_node` and `se_provision`) must be identical; in the older ones the functions they share must be the same as in the newest, except `receive` and `receiveStatus`,
which were changed between versions to return the chip's error status. `tools/test_docs.py` checks both.

<!-- api:atecc:start -->
| Copy in | Lines | SHA-256 (first 8) |
|---|---|---|
| `firmware/se_aes_test/atecc_io.h` | 176 | `528dd485` |
| `firmware/se_lock_config/atecc_io.h` | 126 | `9cc09466` |
| `firmware/se_lora_node/atecc_io.h` | 189 | `6f3f44c4` |
| `firmware/se_provision/atecc_io.h` | 189 | `6f3f44c4` |

| Function | `se_aes_test` | `se_lock_config` | `se_lora_node` | `se_provision` |
|---|---|---|---|---|
| `aesEncrypt` | yes |  | yes | yes |
| `commandData` | yes |  | yes | yes |
| `commandStatus` | yes |  | yes | yes |
| `crc16` | yes | yes | yes | yes |
| `idle` | yes | yes | yes | yes |
| `lockDataNoCrc` |  |  | yes | yes |
| `lockWithCrc` | yes | yes | yes | yes |
| `nonceLoadTempKey` | yes |  | yes | yes |
| `receive` | yes | yes | yes | yes |
| `receiveStatus` | yes | yes | yes | yes |
| `send` | yes | yes | yes | yes |
| `wake` | yes | yes | yes | yes |
| `writeSlotBlock` | yes |  | yes | yes |
<!-- api:atecc:end -->

## 6. Tests

```text
pip install cryptography
python3 -m unittest discover -s tools -v
```

The cross-check against the STM32 project's `secure_link.c` needs that repository next to this one (`../stm32l0-freertos-sensor-node`) or `STM32_SL` pointing at its
`secure_link/` folder; without it that one test is skipped and says so. CI checks both repositories out side by side.

<!-- api:tests:start -->
| Program | What it checks |
|---|---|
| `tools/test_docs.py` | keeps docs/API.md, the README and the other documents honest: every number they repeat is checked against the code or the evidence it comes from. |
| `tools/test_se_config.py` | PC tests for the ATECC608 configuration designer. |
| `tools/test_se_link.py` | PC tests for firmware/se_lora_node/se_link.c. |
| `tools/test_se_provision.py` | PC tests for step 6 tools. |
| `tools/test_se_pubkey.py` | PC tests for the identity-key checker. |
| `tools/crosscheck/crosscheck.c` | proves the MKR's se_link.c builds packets byte-identical to the STM32 project's secure_link.c, which the Feather receiver runs, and that sl_open() on the receiver side accepts them. |
<!-- api:tests:end -->

What `tools/test_docs.py` checks (this list is generated from the test file):

<!-- api:doctests:start -->
- The README's secure-element layout table gives the same SlotConfig and KeyConfig for slot 0 and slot 10 as the designer produces.
- The 'three configuration bytes were changed (40, 41, 116)' sentence and the measurements row 'Configuration bytes changed | 3' equal what the designer changes in the real chip's dump.
- firmware/se_config_image.h and the copy in every sketch that includes it are exactly the header that tools/se_config.py writes for the real chip's dump.
- The README's identity-key time and per-packet sealing time equal what the logged Serial Monitor output of the board shows (every logged seal time is the same value).
- Every '2,000 packets' in the README, the CRA mapping and the threat model equals the number of cases the cross-check program runs.
- The README's '12 threats' equals the number of distinct SE-nn threat rows in docs/THREAT_MODEL.md.
- The hardware counter limit in the README is 2^21 - 1, and at one packet per 15 s that really is about a year.
- README, se_link.h's comment and its constants all describe a 1-byte id, 4-byte counter and 4-byte MIC, and the CTR block layout adds up to 16 bytes.
- The tables in docs/API.md are exactly what tools/make_api_docs.py writes from the code and the evidence today.
- Every public function of the four Python tools has a docstring, so the generated reference has no blank descriptions.
- Every command-line option of the Python tools has help text.
- Every Python file in tools/ is a documented tool, a test, or the generator itself, and every folder in firmware/ has an entry in the sketch table.
- A second, simpler reading of se_link.h finds the same functions and #define constants as appear in the generated C tables.
- Every folder and tool in the README's repository layout exists, every sketch folder and tool file is in it, and every test file has a command in 'Build and test'.
- Every file or folder named in backticks in the README and the documents exists in the repository (the git-ignored secrets folder and build outputs excepted); the STM32 project's files are looked for in that project when it is next to this one.
- The Python example in API.md runs, and the C example compiles with warnings as errors, links with the real se_link.c and returns the packet length 12.
- atecc_io.h in se_lora_node and se_provision are identical; in the older sketches every function that also exists in the newest copy is the same text, except receive and receiveStatus.
- The packet code that runs on the MKR builds packets byte-identical to the STM32 project's secure_link.c, and the receiver's sl_open accepts them (the cross-check program).
- The CI workflow installs cryptography, checks out both repositories side by side, runs every test with 'unittest discover -s tools', and triggers on push to main and on pull requests.
- .gitignore ignores __pycache__ and the built cross-check program, and git tracks no bytecode file.
<!-- api:doctests:end -->

## 7. Limits of this reference

- The sketches are not compiled in CI (there is no Arduino toolchain there). Their behaviour on the chip is evidenced by the Serial Monitor output in `docs/`, not re-tested.
- The measured times in the README (key generation, sealing a packet) come from the board; the tests check the README against the logged output, not the chip.
- The examples run on the PC. The C example uses a stand-in for the chip's AES.
