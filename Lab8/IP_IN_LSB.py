#!/usr/bin/env python3
from PIL import Image

def set_LSB(value, bit):
    if bit == '0':
        return value & 254
    return value | 1

payload = "TARGET:192.168.1.50"

with Image.open("compay_logo.png") as img:
    img = img.convert("RGBA")

pixels = list(img.getdata())
newArray = pixels[:]

for i, char in enumerate(payload):
    byte = bin(ord(char))[2:].zfill(8)
    pixel1_idx = i * 2
    pixel2_idx = i * 2 + 1
    
    r1, g1, b1, a1 = pixels[pixel1_idx]
    r2, g2, b2, a2 = pixels[pixel2_idx]
    
    r1 = set_LSB(r1, byte[0])
    g1 = set_LSB(g1, byte[1])
    b1 = set_LSB(b1, byte[2])
    a1 = set_LSB(a1, byte[3])
    
    r2 = set_LSB(r2, byte[4])
    g2 = set_LSB(g2, byte[5])
    b2 = set_LSB(b2, byte[6])
    a2 = set_LSB(a2, byte[7])
    
    newArray[pixel1_idx] = (r1, g1, b1, a1)
    newArray[pixel2_idx] = (r2, g2, b2, a2)

out = img.copy()
out.putdata(newArray)
out.save("company_logo_stego.png")

print("[HIDE] company_logo_stego.png saved", flush=True)
