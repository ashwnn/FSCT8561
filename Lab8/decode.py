#!/usr/bin/env python3

import os
import stepic
from PIL import Image


if __name__ == "__main__":
    SECRET_IMAGE = "profile_secret.png"
    ORIGINAL_IMAGE = "profile.png"

    with Image.open(SECRET_IMAGE) as im:
        hidden = stepic.decode(im)
    ports = [int(p.strip()) for p in hidden.split(",")]
    print(f"[EXTRACT] Hidden port list: {ports}", flush=True)

    print(f"[EXTRACT] Parsed ports: {ports}", flush=True)

    original_size = os.path.getsize(ORIGINAL_IMAGE)
    stego_size = os.path.getsize(SECRET_IMAGE)
    print(f"[INFO] {ORIGINAL_IMAGE} size: {original_size} bytes", flush=True)
    print(f"[INFO] {SECRET_IMAGE} size: {stego_size} bytes", flush=True)
    print(f"[INFO] Size difference: {stego_size - original_size} bytes", flush=True)

    if original_size == stego_size:
        print("[COMPARE] Sizes are the same", flush=True)
    else:
        print("[COMPARE] Sizes are different", flush=True)
