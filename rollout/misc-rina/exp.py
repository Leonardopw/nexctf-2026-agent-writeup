# -*- coding: utf-8 -*-
"""如果你看扁我 —— PNG 高度字段被改小，底部 200 行数据仍在 IDAT 里

思路：
  IHDR 写 2150x1950，但 IDAT 解压后恰好多出 200 行（hint 200）：
    1950*(1+2150*3) = 12,579,450 < 实际 13,869,650，差 200 行。
  把高度改回 2150、重算 IHDR CRC，重新编码即可还原完整图片。
"""
import struct
import sys
import zlib
from pathlib import Path

from PIL import Image

sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
raw = bytearray((HERE / "attachments" / "rina.png").read_bytes())

w, h = struct.unpack(">II", raw[16:24])
i, idat = 8, b""
while i < len(raw):
    ln = struct.unpack(">I", raw[i:i + 4])[0]
    if raw[i + 4:i + 8] == b"IDAT":
        idat += raw[i + 8:i + 8 + ln]
    i += 12 + ln
data = zlib.decompress(idat)
row = 1 + w * 3
extra = len(data) - h * row
real_h = h + extra // row
print(f"[*] IHDR {w}x{h}, IDAT 解压 {len(data)} 字节, 多出 {extra} 字节 = {extra // row} 行, 真实高度 {real_h}")

# 1) 改高度 + 重算 IHDR CRC
struct.pack_into(">I", raw, 20, real_h)
struct.pack_into(">I", raw, 29, zlib.crc32(bytes(raw[12:29])) & 0xFFFFFFFF)
fixed = EV / "rina_fixed.png"
fixed.write_bytes(raw)
print("[*] 写出", fixed)

img = Image.open(fixed)
print("[*] 解码尺寸:", img.size, img.mode)
bottom = img.crop((0, h, w, real_h))
bottom.save(EV / "bottom.png")
print("[*] 底部 200 行:", EV / "bottom.png", bottom.size)
img.save(EV / "rina_full.png")
print("[*] 完整图:", EV / "rina_full.png")
