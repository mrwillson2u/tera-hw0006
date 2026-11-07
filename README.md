# tera-hw0006

Open tools for the **Tera HW0006 Pro** 2D barcode scanner (the one with the little screen) on macOS and Linux. They replace Tera's Windows-only programs.

- `tera_hw0006.py` is a CLI. It can list the scanner's USB interfaces, change any setting from the manual over USB, back up the scanner's flash, and build and load the "commodity code" list, the text the scanner shows on its screen when it reads a known code.
- `PROTOCOL.md` documents the USB protocol, the flash layout and every decoded setting command. It was reverse-engineered from Tera's `DataTools_EN_V1.4.exe` and the user manual.
- `tests/vectors.json` holds byte-exact packets and a full DB image. A port to another language (for example TypeScript + WebHID) should reproduce them.

> **Status: not yet tested on hardware.** Packet layouts, checksums and the image format come from static analysis of the vendor tool. Do the read-only steps first.

## Quick start

```bash
pip3 install hidapi
python3 tera_hw0006.py list                        # USB interfaces with VID 0x0581
python3 tera_hw0006.py -v send %%SpecCode39        # harmless: show firmware version on screen
python3 tera_hw0006.py -v dump backup.bin          # read-only flash backup (double-press trigger after)
python3 tera_hw0006.py build example_items.txt db.img && python3 tera_hw0006.py parse db.img
python3 tera_hw0006.py load example_items.txt      # dry run; add --yes to write
python3 tests/test_vectors.py                      # offline self-test
```

Linux: copy `99-tera-hw0006.rules` to `/etc/udev/rules.d/` to use the scanner without sudo. On macOS the terminal app may need Input Monitoring permission.

## Input format for `build` / `load`

The input is a tab-separated text file, the same format Tera's tool takes. The first line holds the captions. The first column is the code (up to 13 characters). Every other column becomes a `Caption:Value` line on the scanner's screen. Limits: 2000 codes and 200 bytes of text per code.
