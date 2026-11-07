"""Run with: python3 -m pytest tests  (or python3 tests/test_vectors.py)"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tera_hw0006 as t

V = json.load(open(os.path.join(os.path.dirname(__file__), "vectors.json")))


def test_crc():
    assert t.crc16_ccitt_false(b"123456789") == 0x29B1


def test_packets():
    p = V["packets"]
    assert t.pkt_K("%%EnterSet").hex() == p["K %%EnterSet"]
    assert t.pkt_G_erase(0x120000).hex() == p["G erase 0x120000"]
    assert t.pkt_H_write(0x120034, b"\x01\x02\x03").hex() == p["H write 0x120034 [01 02 03]"]
    assert t.pkt_I_read(0x120000, 52).hex() == p["I read 0x120000 n=52"]
    assert t.pkt_J_finish().hex() == p["J finish"]


def test_image_roundtrip():
    e = V["image_from_example_items_txt"]
    img = t.build_image(e["captions"], e["rows"])
    assert img.hex() == e["hex"]
    recs = t.parse_flash(img[t.HDR:])
    assert [r[0] for r in recs] == sorted(r[0] for r in e["rows"])


if __name__ == "__main__":
    test_crc(); test_packets(); test_image_roundtrip(); print("ok")
