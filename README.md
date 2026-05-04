# Chameleon Ultra MFC Dump

Recover keys and dump MIFARE Classic 1K cards using the Chameleon Ultra. Auto-detects PRNG class and routes to nested, staticnested, or hardnested.

**Requires at least one key already valid on the target card** (placed in `dict.txt`). The script uses that key to bootstrap the nested/hardnested attack on the remaining sectors. With zero matching keys it cannot proceed.

## Card support

| Card                                       | Typical SAK | Attack       |
|--------------------------------------------|-------------|--------------|
| MIFARE Classic 1K (NXP S50, "classic")     | `0x08`      | nested       |
| MIFARE Classic 1K (Infineon SLE 66R35)     | `0x88`      | nested       |
| MIFARE Classic 1K EV1 (NXP)                | `0x08`      | hardnested   |
| Magic gen1a / gen2 / gen4 1K clones        | varies      | nested       |
| Fudan FM11RF08 (older silicon, weak PRNG)  | `0x08`      | staticnested |

Detection is automatic via `mf1_detect_prng()` on connect; step `[2/3]` of every run prints `PRNG class: <name>`.

## Setup

Requirements: `bash`, `curl`, `cc`, [`uv`](https://docs.astral.sh/uv/), and `xz`/`liblzma` (`brew install xz` on macOS, `apt install liblzma-dev` on Debian; needed for hardnested).

    ./setup.sh

That fetches the [ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra) source at a pinned commit into `vendor/`, compiles the C crackers into `bin/`, and runs `uv sync`. Idempotent. To bump the upstream pin, edit `CHAMELEON_SHA` in `setup.sh`, delete `vendor/`, re-run.

## Usage

1. Put your known keys in `dict.txt` (one 12-hex key per line, `#` for comments). Not shipped; you create your own. Seed it from prior `<UID>-key.dic` files or public dictionaries (PM3 `mfc_default_keys.dic`, etc.). The script also tries a handful of well-known defaults (`FFFFFFFFFFFF`, `A0A1A2A3A4A5`, `D3F7D3F7D3F7`, `000000000000`, ...) on top of your file.
2. Place the card on the Chameleon's reader.
3. Run:

       uv run python dump_card.py

Flags: `-p PORT` (auto-detected by USB VID `0x6868`), `-d DICT` (default `./dict.txt`), `-o OUTDIR` (default cwd).

The script will:

1. Dictionary attack against every sector.
2. Nested / staticnested / hardnested for sectors still missing, using any already-known key as the source. Auto-retries probabilistic failures.
3. Read all 64 blocks; write the dump.

## Output files

All in `OUTDIR` (cwd by default), prefixed with the lowercase UID:

| File              | Format                                                 |
|-------------------|--------------------------------------------------------|
| `<UID>-key.txt`   | Per-sector keyA/keyB table, human-readable             |
| `<UID>-key.dic`   | One unique key per line (PM3/mfoc dictionary format)   |
| `<UID>-key.bin`   | 16 keyA (96 B) then 16 keyB (96 B), Proxmark3 format   |
| `<UID>-dump.bin`  | Raw 1024-byte card image                               |
| `<UID>-dump.eml`  | Same image, 16 hex bytes per line, for `hf mf eload`   |

## Cloning a dump to a Chameleon slot

The firmware exposes 8 slots numbered 1-8. In the upstream CLI REPL:

    hw slot list                                        # see all slots
    hw slot change -s 3                                 # activate slot 3
    hw slot type -s 3 -t 1001                           # 1001 = MIFARE Classic 1K
    hf mf eload -f path/to/<UID>-dump.eml -t hex        # load emulator memory
    hf mf settings --coll 1                             # present UID from dump block 0
    hw slot update                                      # persist to flash

The slot survives power cycles once `hw slot update` runs.

## Notes

- The script is read-only against the card: only auths and reads, no `mf1_write_*` calls.
- Hardnested is slower than nested: ~30 s to a few minutes nonce acquisition, plus seconds to a few minutes offline crack per key. A full EV1 1K with all keys unknown typically takes 30-60 minutes.
- The dump's trailer blocks are patched with the recovered key bytes since access bits usually hide keyA when read straight off the card.
