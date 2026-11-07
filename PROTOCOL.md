# Tera HW0006 Pro – USB protocol notes

Reverse-engineered from Tera's `DataTools_EN_V1.4.exe` (from `Data_Tools.zip` on the product page) and the HW0006 Pro manual v04.1.01. It was done by static analysis only. Nothing below has been run against a real scanner yet; items marked **unverified** need a hardware check.

## 1. What the vendor tool actually is

The tool is a native 32-bit MFC app built with VS2012. It is not .NET, and it uses no serial port and no driver. It finds the scanner through SetupAPI and `hid.dll` and talks over **plain USB HID reports**, so it works on macOS and Linux through `hidapi` with no kernel driver.

The tool works as follows:

- It matches **VID `0x0581`** and checks **PIDs `0x020C`, `0x0110`, `0x0115`**. `0x020C` is the PID it sets before sending config commands.
- It skips the scanner's keyboard and mouse HID collections (UsagePage/Usage `0x01/0x06` and `0x01/0x02`) and opens the remaining **vendor-defined** collection.
- Every output report starts with **report ID `0xBA`**. The report length is HIDP_CAPS.OutputReportByteLength, probably 64 bytes. **Unverified:** run `tera_hw0006.py list` to check.

## 2. Packet format

`[0]=0xBA` report ID, `[1]` opcode (ASCII letter), `[2]` payload length (& 0x3F), then the payload, then a checksum. Addresses are 32-bit big-endian.

| Op | Hex | Layout | Check | Purpose |
|---|---|---|---|---|
| `K` | 4B | `BA 4B len <ascii…>` | none | Inject a config string as if its barcode had been scanned (`%%EnterSet`, `%%SpecCode94`, …) |
| `G` | 47 | `BA 47 04 A3 A2 A1 A0 sum` | sum8 of bytes 1–6 | Erase 4 KiB SPI-flash sector |
| `H` | 48 | `BA 48 (n+4) A3..A0 data[n] sum` | sum8 of bytes 1..n+6 | Write n ≤ 52 bytes |
| `I` | 49 | `BA 49 05 A3..A0 n sum` | sum8 of bytes 1–7 | Read n bytes. Reply data starts at input-report offset 4 |
| `J` | 4A | `BA 4A 04 00 00 00 00 crcH crcL` | CRC16 of bytes 1–6 | Finish/exit after a load that started with `%%SpecCodeFC` |
| `b` | 62 | `BA 62 02 v … crcH crcL` | CRC16 of bytes 1–2 | Finish used when the device was already in loader mode (v=1 after load, 0 after delete). **Unverified** |

The CRC is **CRC-16/CCITT-FALSE**: poly 0x1021, init 0xFFFF, not reflected. Its check value for "123456789" is 0x29B1.

The tool waits up to 4 s for a write and 1 s for a read. Its error strings tell you which step failed: "Erase/WRITE/SPI Load failure", "SPIE/SPIW/SPIR Check failure", "Out timeout!". **Unverified:** the exact ACK byte meanings.

## 3. Commodity-code ("show info on screen") load sequence

1. Open the vendor interface and send `K "%%EnterSet"`, wait 100 ms, then send `K "%%SpecCodeFC"`. `SpecCodeFC` is an **undocumented "enter loader mode" command**.
2. The scanner re-enumerates. The tool polls for up to 60 s (600 × 100 ms) and then reopens the device.
3. For each 4 KiB sector from `0x120000`: send `G` erase, then `H` writes of 52-byte chunks (78 × 52 + a 40-byte tail), reading each chunk back with `I` and comparing.
4. Send `J` (or `b 01`). Then the user double-presses the trigger to leave loading mode.

The vendor's "delete all data" button runs the same flow but erases only the sector at `0x120000`.

## 4. DB image layout (what gets flashed)

The tool builds the image in a 0xFF-filled buffer. Flash address `0x120000` corresponds to image offset `0x24`, and every pointer inside the image is stored as `image_offset - 0x24`.

| Image offset | Content |
|---|---|
| 0x00 | u32 LE: `end - 8` |
| 0x04 | u32 LE: CRC16-CCITT-FALSE over `image[8:end]` |
| 0x08 | `00 01 00 00`, then u32 LE `0x00120000` (flash address) |
| 0x10 | `01 00 00 00 00 00 00 00` |
| 0x18 | `01 00 00 00 00 00 00 00` |
| 0x20 | `00 00 00 00` |
| 0x40 | u8: records per bucket = n//64 + (1 if n%64 else 0) |
| 0x41 + 17·g | Bucket g (64 buckets): first barcode of the bucket (13 bytes, 0xFF-padded) + u32 **BE** pointer to its index entry |
| 0x524 + 17·k | Index entry k (sorted ascending): barcode (13 bytes, 0xFF-padded) + u32 BE pointer to its record |
| 0x524 + 17·n … | Records: `u8 len` + `len` bytes of text (≤ 200) |

Records are spread over the 64 buckets: the first `n % 64` buckets get one extra record. The record text is `Caption:Value\n` for each column after the barcode column, with captions taken from the TXT's first line.

Limits: 2000 records, 13-character barcodes, 200 text bytes per record, and a 768,000-byte source TXT.

**Unverified:** sort direction and display encoding. Ascending byte order and GBK are the likely choices. To confirm, load a file once with the vendor tool, run `dump` + `parse`, and compare against `build` + `parse` of the same TXT.

## 5. Configuration commands (all sendable over USB with `K`)

Every 1D setting barcode in the manual encodes a `%%…` string. Every QR setting encodes a `>!00…` string with the pattern `>!00{bank}{param:3 hex}{value}.`. Selected decodes:

| Command | Meaning | Command | Meaning |
|---|---|---|---|
| `%%SpecCode93` | Factory reset | `%%SpecCode39` | Show firmware version |
| `%%SpecCode40` | US keyboard layout (41 DE, 42 FR, 43 ES, 44 IT …) | `%%SpecCodeB5`/`B4` | GBK / UTF output |
| `%%SpecCode94/95/96/97` | Beeper off/low/med/high | `%%SpecCode77`/`76` | Vibration on/off |
| `%%SpecCode10`/`11` | Real-time / storage (batch) mode | `%%SpecCode16/17/18` | Upload all / count / clear stored codes |
| `%%SpecCode30/31/33/35/36/38` | Sleep 30 s/1 m/5 m/30 m/never/immediately | `%%SpecCode15` | Show battery |
| `%%SpecCodeAE` | USB-COM (virtual serial) | `%%SpecCodeA8` | 2.4 GHz mode; `%%SpecCode99` pairing |
| `%%SpecCodeAA`/`AB` | BT HID / BT SPP mode | `%%SpecCodeEC` | Set BT name (then scan/send name) |
| `%%SpecCode9A`/`9B` | Add prefix / suffix (then `%%xx` chars) | `%%SpecCode9C/9D/9E/A2/9F` | Terminator CR/LF/CRLF/TAB/none |
| `%%SpecCodeA0`/`A1` + `%%01…%%10` | Hide first/last N chars | `%%SpecCodeA3/A4/A6/A5` | Lower/upper/invert case/off |
| `%%SpecCode1B` | Show time; `C1`/`C2`/`C0` time prefix/suffix/clear | `%%SpecCodeEF`/`EE` | GS replacement on/off |
| `>!0010000.` / `2.` / `3.` | Manual / continuous / sensor trigger | `>!001003{ms}.` | Re-read delay (0,100,300,500,1000,3000 documented) |
| `>!001002{ms}.` | Inter-message delay | `>!00101A0.`/`1.` | Code ID off/on |
| `>!0003101.`/`0.` | QR on/off | `>!0003201.`/`0.` | DataMatrix on/off |
| `>!0000601.`/`0.` | EAN-13 on/off | `>!0000101.`/`0.` | Code 128 on/off |

Undocumented strings seen in the tool or in sibling-model manuals: `%%EnterSet` (enter setup), `%%SpecCodeFC` (loader mode), and `%%SpecCode92` (save current settings as user default, from another manual of the same OEM family).
