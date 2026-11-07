#!/usr/bin/env python3
"""
tera_hw0006.py - open-source macOS/Linux replacement for Tera's Windows "DataTools"
(commodity-code loader) and a host-side configurator for the Tera HW0006 Pro scanner.

Everything here was reverse-engineered from DataTools_EN_V1.4.exe (native MFC/Win32,
HID via SetupAPI/hid.dll) and the HW0006 Pro user manual. See PROTOCOL.md.

STATUS
  verified from the vendor binary : USB IDs, report ID, packet layouts, checksums/CRC,
                                    flash address, chunking, image layout.
  NOT yet verified on hardware    : response/ACK semantics, exact PID-per-mode mapping,
                                    report length on your unit. Start with `list`, `send`
                                    and `dump` (read-only) before you ever run `load`.

Requires:  pip install hidapi
Linux:     install 99-tera-hw0006.rules into /etc/udev/rules.d/ (or run as root)
macOS:     may need Input Monitoring permission for the terminal app.
"""
from __future__ import annotations

import argparse
import struct
import sys
import time

VID = 0x0581
KNOWN_PIDS = {0x020C: "main (used by DataTools for config + load)", 0x0110: "alt PID", 0x0115: "alt PID"}
REPORT_ID = 0xBA
DEFAULT_REPORT_LEN = 64          # bytes INCLUDING the report ID; override with --report-len
FLASH_BASE = 0x120000            # commodity DB location in the scanner's SPI flash
IMAGE_SIZE = 0xE1000             # DataTools' working buffer (filled with 0xFF)
MAX_TXT_BYTES = 0xBB800
MAX_RECORDS = 2000
INFO_MAX = 200                   # bytes of display text per barcode
BARCODE_FIELD = 13
HDR = 0x24                       # in-image offset that maps to FLASH_BASE
SECTOR = 0x1000
CHUNK = 52                       # bytes per 'H' write, as DataTools does

# --------------------------------------------------------------------------------------
# checksums
# --------------------------------------------------------------------------------------

def crc16_ccitt_false(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection, no xorout)."""
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

# --------------------------------------------------------------------------------------
# packet builders  (byte 0 = report ID 0xBA, byte 1 = opcode, byte 2 = payload length)
# --------------------------------------------------------------------------------------

def pkt_K(text: str) -> bytes:
    """'K' - inject a configuration string exactly as if its barcode had been scanned."""
    raw = text.encode("ascii")
    if len(raw) > 61:
        raise ValueError("command string too long for one report")
    return bytes([REPORT_ID, 0x4B, len(raw) & 0x3F]) + raw


def pkt_G_erase(addr: int) -> bytes:
    """'G' - erase the 4 KiB SPI sector at addr.  sum8 over bytes[1..6]."""
    body = bytes([0x47, 0x04]) + addr.to_bytes(4, "big")
    return bytes([REPORT_ID]) + body + bytes([sum8(body)])


def pkt_H_write(addr: int, data: bytes) -> bytes:
    """'H' - write up to 52 bytes at addr.  sum8 over bytes[1..len+6]."""
    if len(data) > CHUNK:
        raise ValueError("chunk too large")
    body = bytes([0x48, (len(data) + 4) & 0x3F]) + addr.to_bytes(4, "big") + data
    return bytes([REPORT_ID]) + body + bytes([sum8(body)])


def pkt_I_read(addr: int, n: int) -> bytes:
    """'I' - read n (<=63) bytes at addr; reply carries data at input-report offset 4."""
    body = bytes([0x49, 0x05]) + addr.to_bytes(4, "big") + bytes([n & 0x3F])
    return bytes([REPORT_ID]) + body + bytes([sum8(body)])


def pkt_J_finish() -> bytes:
    """'J' - sent at the end of a load when the scanner was switched in via %%SpecCodeFC."""
    body = bytes([0x4A, 0x04, 0x00, 0x00, 0x00, 0x00])
    crc = crc16_ccitt_false(body)
    return bytes([REPORT_ID]) + body + crc.to_bytes(2, "big")


def pkt_b_finish(value: int) -> bytes:
    """'b' - alternative finish used when the device was already in loader mode (value 1 after
    load, 0 after delete).  DataTools only CRCs the first two body bytes; bytes 4-6 are whatever
    was left in its buffer, so we send zeros. Unverified."""
    body = bytes([0x62, 0x02, value & 0xFF, 0x00, 0x00, 0x00])
    crc = crc16_ccitt_false(body[:2])
    return bytes([REPORT_ID]) + body + crc.to_bytes(2, "big")

# --------------------------------------------------------------------------------------
# device transport
# --------------------------------------------------------------------------------------

class Scanner:
    def __init__(self, path: bytes | None = None, report_len: int = DEFAULT_REPORT_LEN,
                 verbose: bool = False, dry_run: bool = False):
        self.report_len = report_len
        self.verbose = verbose
        self.dry_run = dry_run
        self.dev = None
        if dry_run:
            return
        import hid  # pip install hidapi
        if path is None:
            path = pick_vendor_interface()
        self.dev = hid.device()
        self.dev.open_path(path)

    def close(self):
        if self.dev:
            self.dev.close()

    def xfer(self, pkt: bytes, timeout_ms: int = 1000, expect_reply: bool = True) -> bytes | None:
        out = pkt.ljust(self.report_len, b"\x00")
        if self.verbose or self.dry_run:
            print("  >>", out[: max(len(pkt), 12)].hex(" "))
        if self.dry_run:
            return None
        n = self.dev.write(out)
        if n < 0:
            raise IOError("HID write failed (wrong --report-len? permissions?)")
        if not expect_reply:
            return None
        r = bytes(self.dev.read(self.report_len, timeout_ms))
        if self.verbose:
            print("  <<", r.hex(" ") if r else "(timeout)")
        if r and r[0] != REPORT_ID:          # some backends strip the report ID
            r = bytes([REPORT_ID]) + r
        return r


def enumerate_devices():
    import hid
    return [d for d in hid.enumerate(VID, 0)]


def pick_vendor_interface() -> bytes:
    """DataTools skips interfaces whose (UsagePage<<8|Usage) is 0x0102 (mouse) or 0x0106
    (keyboard) and talks to the remaining (vendor-defined) HID interface."""
    devs = enumerate_devices()
    if not devs:
        sys.exit("No device with VID 0x0581 found. Plug the scanner in via USB cable and switch it on.")
    vendor = [d for d in devs if ((d.get("usage_page", 0) << 8) | d.get("usage", 0)) not in (0x0102, 0x0106)]
    pref = [d for d in vendor if d["product_id"] == 0x020C] or vendor
    if not pref:
        sys.exit("Only keyboard/mouse interfaces found; run `list` and pass --path explicitly.")
    return pref[0]["path"]

# --------------------------------------------------------------------------------------
# commodity database image  (TXT -> binary, binary -> records)
# --------------------------------------------------------------------------------------

def read_tab_txt(path: str, encoding: str):
    raw = open(path, "rb").read()
    if len(raw) > MAX_TXT_BYTES:
        raise SystemExit("file larger than the vendor limit (768000 bytes)")
    for enc in ([encoding] if encoding else ["utf-8-sig", "gbk", "cp1252"]):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    lines = [l for l in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if l.strip()]
    rows = [l.split("\t") for l in lines]
    return rows[0], rows[1:]


def build_image(captions, rows, strict13=False, out_encoding="gbk") -> bytes:
    """Re-implementation of DataTools' converter (0x405230). First column = barcode
    (<=13 chars), other columns become 'Caption:Value\\n' lines on the scanner's screen."""
    if len(rows) > MAX_RECORDS:
        raise SystemExit(f"{len(rows)} rows > {MAX_RECORDS} limit")
    recs, seen = [], {}
    for ln, row in enumerate(rows, start=2):
        bc = row[0].strip()
        if len(bc) > BARCODE_FIELD or (strict13 and len(bc) != BARCODE_FIELD):
            raise SystemExit(f"line {ln}: barcode '{bc}' must be {'exactly' if strict13 else 'at most'} 13 chars")
        if bc in seen:
            raise SystemExit(f"lines {seen[bc]} and {ln} have the same barcode")
        seen[bc] = ln
        info = "".join(f"{captions[j].strip()}:{(row[j] if j < len(row) else '').strip()}\n"
                       for j in range(1, len(captions)))
        recs.append((bc.encode("ascii"), info.encode(out_encoding, errors="replace")[:INFO_MAX]))
    recs.sort(key=lambda r: r[0])                     # ascending (see PROTOCOL.md)

    n = len(recs)
    img = bytearray(b"\xff" * IMAGE_SIZE)
    q, r = divmod(n, 64)
    img[0x40] = q + (1 if r else 0)                   # max records per bucket
    idx_pos = 0x524
    rec_pos = 0x524 + 17 * n
    i = 0
    for g in range(64):                               # 64 buckets, first r get q+1 records
        if g >= n:
            break
        ent = 0x41 + 17 * g
        img[ent:ent + 13] = recs[i][0].ljust(13, b"\xff")
        img[ent + 13:ent + 17] = (idx_pos - HDR).to_bytes(4, "big")
        for _ in range(q + (1 if g < r else 0)):
            bc, info = recs[i]
            img[idx_pos:idx_pos + 13] = bc.ljust(13, b"\xff")
            img[idx_pos + 13:idx_pos + 17] = (rec_pos - HDR).to_bytes(4, "big")
            img[rec_pos] = len(info)
            img[rec_pos + 1:rec_pos + 1 + len(info)] = info
            rec_pos += 1 + len(info)
            idx_pos += 17
            i += 1
    end = rec_pos
    img[0x08:0x24] = (bytes([0x00, 0x01, 0x00, 0x00]) + FLASH_BASE.to_bytes(4, "little")
                      + bytes([1, 0, 0, 0, 0, 0, 0, 0]) + bytes([1, 0, 0, 0, 0, 0, 0, 0]) + bytes(4))
    struct.pack_into("<I", img, 0, end - 8)
    struct.pack_into("<I", img, 4, crc16_ccitt_false(bytes(img[8:end])))
    return bytes(img[:end])


def parse_flash(flash: bytes, encoding="gbk"):
    """Parse the DB as stored in flash (i.e. image[0x24:]). Pointers are flash-relative."""
    img = b"\xff" * HDR + flash
    per_bucket = img[0x40]
    if per_bucket in (0, 0xFF):
        return []
    out = []
    # walk the flat 17-byte index until 0xFF padding
    pos = 0x524
    while pos + 17 <= len(img) and img[pos] != 0xFF:
        bc = img[pos:pos + 13].rstrip(b"\xff").decode("ascii", "replace")
        ptr = int.from_bytes(img[pos + 13:pos + 17], "big") + HDR
        if ptr >= len(img):
            break
        ln = img[ptr]
        out.append((bc, img[ptr + 1:ptr + 1 + ln].decode(encoding, "replace")))
        pos += 17
    return out

# --------------------------------------------------------------------------------------
# high-level operations
# --------------------------------------------------------------------------------------

def send_config(sc: Scanner, cmds, enter=True):
    if enter:
        print("%%EnterSet ->", _hx(sc.xfer(pkt_K("%%EnterSet"))))
        time.sleep(0.1)
    for c in cmds:
        print(f"{c} ->", _hx(sc.xfer(pkt_K(c))))
        time.sleep(0.1)


def enter_loader(sc: Scanner, args) -> Scanner:
    print("Switching scanner into loader mode (%%EnterSet, %%SpecCodeFC)...")
    sc.xfer(pkt_K("%%EnterSet"))
    time.sleep(0.1)
    sc.xfer(pkt_K("%%SpecCodeFC"))
    if sc.dry_run:
        return sc
    sc.close()
    for _ in range(600):                              # DataTools waits up to 600 x 100 ms
        time.sleep(0.1)
        try:
            return Scanner(None, args.report_len, args.verbose)
        except Exception:
            continue
    sys.exit("scanner did not re-appear after %%SpecCodeFC")


def read_flash(sc: Scanner, addr: int, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        n = min(CHUNK, size - len(buf))
        r = sc.xfer(pkt_I_read(addr + len(buf), n))
        if not r:
            raise IOError(f"no reply reading 0x{addr + len(buf):06x}")
        buf += r[4:4 + n]
    return bytes(buf)


def load_image(sc: Scanner, flash_data: bytes, finish_with_J=True):
    total = len(flash_data)
    sectors = (total + SECTOR - 1) // SECTOR
    for s in range(sectors):
        base = FLASH_BASE + s * SECTOR
        if not sc.xfer(pkt_G_erase(base), timeout_ms=4000) and not sc.dry_run:
            raise IOError(f"erase failed @0x{base:06x}")
        off = s * SECTOR
        while off < min(total, (s + 1) * SECTOR):
            n = min(CHUNK, (s + 1) * SECTOR - off, total - off)
            chunk = flash_data[off:off + n]
            if not sc.xfer(pkt_H_write(FLASH_BASE + off, chunk)) and not sc.dry_run:
                raise IOError(f"write failed @0x{FLASH_BASE + off:06x}")
            if not sc.dry_run:
                back = read_flash(sc, FLASH_BASE + off, n)
                if back != chunk:
                    raise IOError(f"verify mismatch @0x{FLASH_BASE + off:06x}")
            off += n
        print(f"\r  {min(100, (s + 1) * 100 // sectors)}%", end="", flush=True)
    print()
    sc.xfer(pkt_J_finish() if finish_with_J else pkt_b_finish(1))
    print("Done - double-press the trigger to leave loading mode (as the vendor manual says).")


def _hx(r):
    return "(no reply)" if not r else r[:16].hex(" ")

# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", help="hidapi device path from `list` (default: auto-pick vendor interface)")
    ap.add_argument("--report-len", type=int, default=DEFAULT_REPORT_LEN)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list HID interfaces with VID 0x0581")

    p = sub.add_parser("send", help="send config strings (e.g. %%SpecCode94 = beeper off)")
    p.add_argument("commands", nargs="+")
    p.add_argument("--no-enter", action="store_true", help="don't prefix with %%EnterSet")

    p = sub.add_parser("build", help="convert a tab-separated TXT into a DB image (offline)")
    p.add_argument("txt"); p.add_argument("out")
    p.add_argument("--strict13", action="store_true", help="require exactly 13-char barcodes")
    p.add_argument("--encoding", default=None, help="input encoding (default: auto)")
    p.add_argument("--display-encoding", default="gbk")

    p = sub.add_parser("parse", help="print records from a built image (.img) or flash dump (.bin)")
    p.add_argument("file")
    p.add_argument("--display-encoding", default="gbk")

    p = sub.add_parser("dump", help="READ-ONLY: enter loader mode and dump flash (backup!)")
    p.add_argument("out"); p.add_argument("--addr", type=lambda x: int(x, 0), default=FLASH_BASE)
    p.add_argument("--size", type=lambda x: int(x, 0), default=0x10000)

    p = sub.add_parser("load", help="WRITES FLASH: build from TXT and load to the scanner")
    p.add_argument("txt")
    p.add_argument("--strict13", action="store_true")
    p.add_argument("--encoding", default=None)
    p.add_argument("--display-encoding", default="gbk")
    p.add_argument("--yes", action="store_true", help="actually write (otherwise dry-run)")

    a = ap.parse_args()
    path = a.path.encode() if a.path else None

    if a.cmd == "list":
        for d in enumerate_devices():
            up = (d.get("usage_page", 0) << 8) | d.get("usage", 0)
            kind = {0x0102: "mouse", 0x0106: "keyboard"}.get(up, "VENDOR <- protocol interface")
            print(f"{d['vendor_id']:04x}:{d['product_id']:04x} if={d.get('interface_number')} "
                  f"usage={d.get('usage_page', 0):#06x}/{d.get('usage', 0):#06x} [{kind}] "
                  f"{d.get('product_string')!r} path={d['path'].decode(errors='replace')}")
        return

    if a.cmd == "build":
        caps, rows = read_tab_txt(a.txt, a.encoding)
        img = build_image(caps, rows, a.strict13, a.display_encoding)
        open(a.out, "wb").write(img)
        print(f"{len(rows)} records, image {len(img)} bytes, flash payload {len(img) - HDR} bytes")
        return

    if a.cmd == "parse":
        data = open(a.file, "rb").read()
        flash = data[HDR:] if data[8:12] == b"\x00\x01\x00\x00" else data   # built image vs raw dump
        for bc, info in parse_flash(flash, a.display_encoding):
            print(bc, "|", info.replace("\n", " / "))
        return

    sc = Scanner(path, a.report_len, a.verbose, dry_run=(a.cmd == "load" and not a.yes))
    try:
        if a.cmd == "send":
            send_config(sc, a.commands, enter=not a.no_enter)
        elif a.cmd == "dump":
            sc = enter_loader(sc, a)
            data = read_flash(sc, a.addr, a.size)
            open(a.out, "wb").write(data)
            print(f"wrote {len(data)} bytes; leaving loader mode")
            sc.xfer(pkt_J_finish())
        elif a.cmd == "load":
            caps, rows = read_tab_txt(a.txt, a.encoding)
            img = build_image(caps, rows, a.strict13, a.display_encoding)
            if sc.dry_run:
                print("DRY RUN (add --yes to write). Packets that would be sent:")
            sc = enter_loader(sc, a)
            load_image(sc, img[HDR:])
    finally:
        sc.close()


if __name__ == "__main__":
    main()
