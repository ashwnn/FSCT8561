#!/usr/bin/env python3
from PIL import Image
import stepic

ports = [80, 443, 3478, 5060]
data_string = ",".join(map(str, ports))
data_bytes = data_string.encode('utf-8')

with Image.open("profile.png") as img:
    encoded = stepic.encode(img, data_bytes)

encoded.save("profile_secret.png")

print("[HIDE] profile_secret.png saved", flush=True)
