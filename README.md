# dump_card.py

Recover all MIFARE Classic 1K keys from a card on the Chameleon Ultra reader, then dump the full card.

## Setup

This repo depends on the [ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra) source tree (Python modules + C cracker sources), pinned to a specific upstream commit. The dependency is fetched on demand into gitignored `vendor/`, never copied into git history.

Requirements: `bash`, `curl`, `cc`, [`uv`](https://docs.astral.sh/uv/), and a Chameleon Ultra plugged in.

    ./setup.sh

That single command:

1. Downloads the ChameleonUltra source tarball at the pinned SHA.
2. Extracts only `software/script/` and `software/src/` into `vendor/ChameleonUltra/`.
3. Compiles the C crackers (`nested`, `staticnested`, `darkside`, `mfkey32{,v2}`, `mfkey64`, plus the new `staticnested_*` variants) into `bin/`.
4. Runs `uv sync` to install Python deps (`pyserial`, `colorama`, `prompt-toolkit`) into `.venv/`.

Re-runs are idempotent. To bump the upstream version, edit `CHAMELEON_SHA` in `setup.sh`, delete `vendor/`, and re-run.

## Dictionary file

The script needs a key dictionary at the path passed via `-d` (default `./dict.txt`). It is **not shipped with this repo**; keys are sensitive and operator-specific, so you create your own.

Format: one 12-character hex key per line. Lines starting with `#` and blank lines are ignored. Example:

    # my keys
    A0A1A2A3A4A5
    D3F7D3F7D3F7

Sources to seed your dictionary:

- Keys you've recovered from prior cards (`<UID>-key.dic` files from earlier runs).
- Public dictionaries shipped with Proxmark3 / mfoc / mfcuk: `mfc_default_keys.dic`, `extended_std.dic`, etc.

The script also automatically tries a handful of well-known defaults (`FFFFFFFFFFFF`, `A0A1A2A3A4A5`, `D3F7D3F7D3F7`, `000000000000`, ...) even if they're not in your file.

## Usage

    uv run python dump_card.py [-p PORT] [-d DICT] [-o OUTDIR]

Flags:

- `-p, --port`   serial port (auto-detected by USB VID `0x6868` if omitted)
- `-d, --dict`   key dictionary file, one 12-hex key per line (default `./dict.txt`)
- `-o, --out`    output directory (default cwd)

Place the card on the reader before running. The script will:

1. **Resume**: if `<UID>-key.txt` already exists in `OUTDIR`, re-verify each prior key against the live card and skip work for sectors that are still good. A re-run with all keys known takes ~2 seconds.
2. **Dictionary attack**: try every key in the dictionary against every sector for both A and B keys.
3. **Nested attack**: for sectors still missing a key, run nested using any key already recovered. Auto-retries up to 3 times per sector.
4. **Read all 64 blocks** using whichever key works per sector.

## Output files

All written to `OUTDIR` (defaults to cwd), prefixed with the lowercase UID:

| File              | Format                                                 |
|-------------------|--------------------------------------------------------|
| `<UID>-key.txt`   | Per-sector keyA/keyB table, human-readable             |
| `<UID>-key.dic`   | One unique key per line (PM3/mfoc dictionary format)   |
| `<UID>-key.bin`   | 16 keyA (96 B) then 16 keyB (96 B), Proxmark3 format   |
| `<UID>-dump.bin`  | Raw 1024-byte card image                               |
| `<UID>-dump.eml`  | Same image, 16 hex bytes per line, for `hf mf eload`   |

## Writing the dump back to a Chameleon slot

The Chameleon Ultra firmware always exposes **8 slots numbered 1-8** regardless of whether you've put data in them. To see what's currently in each slot, in the upstream CLI REPL:

    hw slot list

To clone a dumped card into, say, slot 3:

    hw slot change -s 3                        # activate slot 3
    hw slot type -s 3 -t 1001                  # 1001 = MIFARE Classic 1K
    hf mf eload -f path/to/<UID>-dump.eml -t hex
    hf mf settings --coll 1                    # use UID from dump block 0
    hw slot update                             # persist to flash

Tag type numbers:

| Number | Tag                  |
|-------:|----------------------|
|   1000 | MIFARE Classic Mini  |
|   1001 | MIFARE Classic 1K    |
|   1002 | MIFARE Classic 2K    |
|   1003 | MIFARE Classic 4K    |
|    100 | EM410x               |

The slot keeps its data across power cycles once `hw slot update` persists to flash.

## Notes

- The script handles **nested** and **staticnested** cards automatically (it calls `mf1_detect_prng` first). Hardnested cards (MIFARE Classic 1K EV1) fail with a clear message; the cracker is not currently bundled into `bin/` since it requires extra dependencies (xz). Build it separately from `vendor/ChameleonUltra/src/HardnestedRecovery/` if you need it.
- Dictionary attack is silent during failures but prints `trying N keys ... none` per sector so you can see progress.
- A failed nested attempt is normal because the attack is probabilistic; the script retries up to 3 times before giving up on a sector.
- The `<UID>-dump.bin` patches the trailer key bytes from what we recovered; don't trust the keyA bytes that come straight off the card (access bits often hide them).
