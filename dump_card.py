#!/usr/bin/env python3
"""
Recover all MIFARE Classic 1K keys from a card on the Chameleon Ultra reader,
then dump the full card.

Strategy per sector:
    1. If <UID>-key.txt from a prior run is in the output directory, load
       its keys and skip work for sectors already cracked.
    2. Try every key in the dictionary (custom.txt) for both A and B.
    3. For sectors still unknown, run a nested attack using any key
       already recovered from another sector. Retried up to 3 times since
       nested key acquisition is probabilistic.

Outputs (next to this script's invocation cwd):
    <UID>-key.txt   human-readable per-sector key list
    <UID>-key.dic   one unique 12-hex key per line  [PM3/mfoc dictionary format]
    <UID>-key.bin   16 keyA (96 B) followed by 16 keyB (96 B)  [Proxmark3 format]
    <UID>-dump.bin  raw 1024-byte card image
    <UID>-dump.eml  same image, 16 hex bytes per line
"""

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "vendor/ChameleonUltra/script"))

import chameleon_cmd
import chameleon_com
import serial.tools.list_ports

CHAMELEON_USB_VID = 0x6868

KEY_A = 0x60
KEY_B = 0x61
SECTOR_COUNT = 16          # MIFARE Classic 1K
BLOCKS_PER_SECTOR = 4
BIN_DIR = REPO_ROOT / "bin"


def first_block(sector: int) -> int:
    return sector * BLOCKS_PER_SECTOR


def trailer_block(sector: int) -> int:
    return sector * BLOCKS_PER_SECTOR + (BLOCKS_PER_SECTOR - 1)


def load_dictionary(path: Path) -> list[bytes]:
    keys: list[bytes] = []
    seen: set[bytes] = set()
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not re.fullmatch(r"[0-9a-fA-F]{12}", line):
                continue
            k = bytes.fromhex(line)
            if k not in seen:
                seen.add(k)
                keys.append(k)
    # Always try the all-default keys too, cheap and high-yield.
    for default in (
        "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7", "000000000000",
        "B0B1B2B3B4B5", "4D3A99C351DD", "1A982C7E459A", "AABBCCDDEEFF",
    ):
        k = bytes.fromhex(default)
        if k not in seen:
            seen.add(k)
            keys.append(k)
    return keys


def find_chameleon_port() -> str | None:
    """Return the device path of the first attached Chameleon, or None."""
    for p in serial.tools.list_ports.comports():
        if p.vid == CHAMELEON_USB_VID:
            return p.device
    return None


def auth(cmd: chameleon_cmd.ChameleonCMD, block: int, key_type: int, key: bytes) -> bool:
    try:
        return bool(cmd.mf1_auth_one_key_block(block, key_type, key))
    except Exception:
        return False


def load_existing_keys(path: Path, cmd, known) -> int:
    """If a previous-run keys file exists, verify each key still authenticates and
    populate `known`. Returns the number of keys loaded."""
    if not path.exists():
        return 0
    loaded = 0
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            sector = int(parts[0])
        except ValueError:
            continue
        if not 0 <= sector < SECTOR_COUNT:
            continue
        for kt_name, kt_val, hex_str in (("A", KEY_A, parts[1]), ("B", KEY_B, parts[2])):
            if not re.fullmatch(r"[0-9a-fA-F]{12}", hex_str):
                continue
            key = bytes.fromhex(hex_str)
            if auth(cmd, first_block(sector), kt_val, key):
                known[sector][kt_name] = key
                loaded += 1
    return loaded


def dictionary_attack(cmd, dictionary, known):
    """For each sector with an unknown A or B key, try every key in the dictionary."""
    for sector in range(SECTOR_COUNT):
        blk = first_block(sector)
        for kt_name, kt_val in (("A", KEY_A), ("B", KEY_B)):
            if known[sector][kt_name] is not None:
                continue
            print(f"  sector {sector:2d} key {kt_name}: trying {len(dictionary)} keys ... ",
                  end="", flush=True)
            found = None
            for key in dictionary:
                if auth(cmd, blk, kt_val, key):
                    found = key
                    break
            if found is not None:
                known[sector][kt_name] = found
                print(f"{found.hex().upper()}")
            else:
                print("none")


PRNG_STATIC = 0
PRNG_NESTED = 1
PRNG_HARD = 2

NESTED_RETRIES = 3


def run_decryptor(name: str, cmd_args: list[str]) -> list[bytes]:
    """Invoke ./bin/<name> and return all 12-hex candidates from stdout."""
    proc = subprocess.run([str(BIN_DIR / name), *cmd_args],
                          cwd=str(BIN_DIR), capture_output=True, text=True, timeout=120)
    return [bytes.fromhex(m) for m in re.findall(r"([0-9a-fA-F]{12})", proc.stdout)]


def nested_recover(cmd, prng_type, src_block, src_type, src_key, tgt_block, tgt_type) -> bytes | None:
    """Acquire NT pairs from device, then run ./bin/(static)nested to crack the target."""
    if prng_type == PRNG_STATIC:
        nt_obj = cmd.mf1_static_nested_acquire(src_block, src_type, src_key, tgt_block, tgt_type)
        args = [f"{nt_obj['uid']}", str(tgt_type)]
        for nt in nt_obj["nts"]:
            args += [str(nt["nt"]), str(nt["nt_enc"])]
        candidates = run_decryptor("staticnested", args)
    else:
        dist = cmd.mf1_detect_nt_dist(src_block, src_type, src_key)
        nts = cmd.mf1_nested_acquire(src_block, src_type, src_key, tgt_block, tgt_type)
        args = [f"{dist['uid']}", str(dist["dist"])]
        for nt in nts:
            args += [str(nt["nt"]), str(nt["nt_enc"]), str(nt["par"])]
        candidates = run_decryptor("nested", args)
    for k in candidates:
        if auth(cmd, tgt_block, tgt_type, k):
            return k
    return None


def pick_source_key(known):
    for s in range(SECTOR_COUNT):
        for st_name, st_val in (("A", KEY_A), ("B", KEY_B)):
            if known[s][st_name] is not None:
                return first_block(s), st_val, known[s][st_name]
    return None


def nested_attack(cmd, known):
    """Walk every still-unknown sector key and try nested using any known key."""
    try:
        prng_type = cmd.mf1_detect_prng()
    except Exception as e:
        print(f"  PRNG detection failed: {e}")
        return
    if prng_type == PRNG_HARD:
        print("  Card is HardNested — not implemented in this script.")
        return
    label = "staticnested" if prng_type == PRNG_STATIC else "nested"
    print(f"  PRNG class: {label}")

    for sector in range(SECTOR_COUNT):
        for kt_name, kt_val in (("A", KEY_A), ("B", KEY_B)):
            if known[sector][kt_name] is not None:
                continue
            src = pick_source_key(known)
            if src is None:
                print("  no known key available, cannot run nested")
                return
            src_block, src_type, src_key = src
            tgt_block = first_block(sector)
            print(f"  sector {sector:2d} key {kt_name}: ", end="", flush=True)
            for attempt in range(1, NESTED_RETRIES + 1):
                try:
                    k = nested_recover(cmd, prng_type, src_block, src_type, src_key,
                                       tgt_block, kt_val)
                except Exception as e:
                    print(f"error: {e}", end=" ")
                    k = None
                if k is not None:
                    known[sector][kt_name] = k
                    print(k.hex().upper())
                    break
                if attempt < NESTED_RETRIES:
                    print(f"retry {attempt}... ", end="", flush=True)
            else:
                print("FAILED")


def read_card(cmd, known) -> bytearray:
    """Read all 64 blocks. Sector trailers come from key bytes we already have."""
    data = bytearray(64 * 16)
    for sector in range(SECTOR_COUNT):
        ka = known[sector]["A"]
        kb = known[sector]["B"]
        # Pick whichever side authed; for trailer block we must compose ourselves
        # since reading the trailer with key A often returns zeros for keyA.
        for i in range(BLOCKS_PER_SECTOR):
            blk = first_block(sector) + i
            block_data = None
            if i == BLOCKS_PER_SECTOR - 1:
                # trailer: synthesise from known keys + default access bits if we can,
                # but prefer reading with key B which does return both halves on most cards
                if kb is not None:
                    try:
                        block_data = bytes(cmd.mf1_read_one_block(blk, KEY_B, kb))
                    except Exception:
                        block_data = None
            if block_data is None:
                for kt_val, key in ((KEY_A, ka), (KEY_B, kb)):
                    if key is None:
                        continue
                    try:
                        block_data = bytes(cmd.mf1_read_one_block(blk, kt_val, key))
                        break
                    except Exception:
                        continue
            if block_data is None:
                print(f"  blk {blk:2d}: UNREADABLE")
                continue
            # Patch the trailer's key bytes from what we know (most readers return
            # zeros for the key A field even when we authed successfully).
            if i == BLOCKS_PER_SECTOR - 1:
                patched = bytearray(block_data)
                if ka is not None:
                    patched[0:6] = ka
                if kb is not None:
                    patched[10:16] = kb
                block_data = bytes(patched)
            data[blk * 16:(blk + 1) * 16] = block_data
    return data


def write_outputs(uid_hex: str, known, dump: bytes, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    txt = out_dir / f"{uid_hex}-key.txt"
    dic = out_dir / f"{uid_hex}-key.dic"
    binkey = out_dir / f"{uid_hex}-key.bin"
    bindump = out_dir / f"{uid_hex}-dump.bin"
    eml = out_dir / f"{uid_hex}-dump.eml"

    with txt.open("w") as fh:
        fh.write(f"# UID {uid_hex}\n# sector  keyA          keyB\n")
        for s in range(SECTOR_COUNT):
            a = known[s]["A"].hex().upper() if known[s]["A"] else "------------"
            b = known[s]["B"].hex().upper() if known[s]["B"] else "------------"
            fh.write(f"{s:7d}  {a}  {b}\n")

    unique_keys = []
    seen = set()
    for s in range(SECTOR_COUNT):
        for kt in ("A", "B"):
            k = known[s][kt]
            if k is not None and k not in seen:
                seen.add(k)
                unique_keys.append(k)
    with dic.open("w") as fh:
        fh.write(f"# UID {uid_hex} ({len(unique_keys)} unique keys)\n")
        for k in unique_keys:
            fh.write(k.hex().upper() + "\n")

    with binkey.open("wb") as fh:
        for s in range(SECTOR_COUNT):
            fh.write(known[s]["A"] if known[s]["A"] else b"\x00" * 6)
        for s in range(SECTOR_COUNT):
            fh.write(known[s]["B"] if known[s]["B"] else b"\x00" * 6)

    bindump.write_bytes(dump)
    with eml.open("w") as fh:
        for i in range(0, len(dump), 16):
            fh.write(dump[i:i + 16].hex() + "\n")

    print(f"\nWrote:\n  {txt}\n  {dic}\n  {binkey}\n  {bindump}\n  {eml}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-p", "--port", default=None,
                    help="serial port (auto-detected by USB VID if omitted)")
    ap.add_argument("-d", "--dict", default=str(REPO_ROOT / "dict.txt"))
    ap.add_argument("-o", "--out", default=".", help="output directory")
    args = ap.parse_args()

    dictionary = load_dictionary(Path(args.dict))
    print(f"Loaded {len(dictionary)} dictionary keys from {args.dict}")

    port = args.port or find_chameleon_port()
    if port is None:
        print("No Chameleon device found on USB. Plug it in or specify --port.")
        sys.exit(1)
    print(f"Connecting to {port}")
    com = chameleon_com.ChameleonCom()
    com.open(port)
    cmd = chameleon_cmd.ChameleonCMD(com)

    if not cmd.is_device_reader_mode():
        print("Switching to reader mode...")
        cmd.set_device_reader_mode(True)
        time.sleep(0.3)

    scan = cmd.hf14a_scan()
    if not scan:
        print("No card detected on the reader.")
        com.close()
        sys.exit(1)
    tag = scan[0]
    uid_bytes = tag["uid"]
    uid_hex = uid_bytes.hex().upper()
    uid_int_hex = f"{int.from_bytes(uid_bytes, 'big'):08x}"
    print(f"Card UID  : {uid_hex}")
    print(f"     ATQA : {tag['atqa'].hex().upper()}  SAK: {tag['sak'].hex().upper()}")

    # known[sector][key_type] = bytes or None
    known = [{"A": None, "B": None} for _ in range(SECTOR_COUNT)]

    out_dir = Path(args.out)
    prev_keys = out_dir / f"{uid_int_hex}-key.txt"
    print(f"\n[0/3] Loading prior keys from {prev_keys} (if any)...")
    loaded = load_existing_keys(prev_keys, cmd, known)
    if loaded:
        print(f"  resumed {loaded}/{SECTOR_COUNT * 2} keys from previous run")
    else:
        print("  none")

    print("\n[1/3] Dictionary attack...")
    dictionary_attack(cmd, dictionary, known)

    missing = sum(1 for s in known for kt in ("A", "B") if s[kt] is None)
    if missing:
        print(f"\n[2/3] Nested attack ({missing} keys still missing)...")
        nested_attack(cmd, known)
    else:
        print("\n[2/3] All keys found via dictionary, skipping nested.")

    print("\n[3/3] Reading all blocks...")
    dump = read_card(cmd, known)

    write_outputs(uid_int_hex, known, dump, out_dir)
    com.close()


if __name__ == "__main__":
    main()
