import base64
import csv
import io
import os
import sys
from datetime import datetime
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout

import exifread
from PIL import Image

# extensions to scan for
EXTENSIONS = {".jpg", ".jpeg", ".tif", ".tiff", ".png"}

# common editing software to look for
EDITING_HINTS = ["photoshop", "lightroom", "gimp", "affinity", "snapseed"]

def get_tag(tags, name):
    val = tags.get(name)
    if val is None:
        return ""
    return str(val).replace("\x00", "").strip()

# Convert GPS DMS (degrees, minutes, seconds) to decimal degrees
def gps_to_decimal(vals, ref):
    if vals is None or not hasattr(vals, "values"):
        return ""
    v = list(vals.values)
    if len(v) < 3:
        return ""
    deg = float(v[0].num) / float(v[0].den)
    mins = float(v[1].num) / float(v[1].den)
    secs = float(v[2].num) / float(v[2].den)
    decimal = deg + (mins / 60) + (secs / 3600)
    if ref.upper() in ("S", "W"):
        decimal = -decimal
    return f"{decimal:.6f}"

# Pad and attempt base64 decode; return decoded text if it looks printable
def try_decode_base64(s):
    s = s.strip()
    pad = (-len(s)) % 4
    s += "=" * pad
    try:
        raw = base64.b64decode(s)
        text = raw.decode("utf-8", errors="replace").replace("\x00", "").strip()
        printable = sum(1 for c in text if c.isprintable())
        if text and printable / len(text) >= 0.85:
            return text
    except Exception:
        pass
    return ""


def find_secret(fields):
    # Check each field for base64 or secret-looking content
    for name, val in fields.items():
        if not val:
            continue
        # Try base64 decode if value looks like it could be encoded
        if len(val) >= 16 and val.replace("=", "").isalnum():
            decoded = try_decode_base64(val)
            if decoded:
                return decoded, name, "decoded"
    # Fall back to raw keyword search
    for name, val in fields.items():
        low = (val or "").lower()
        if any(kw in low for kw in ("step", "part", "secret", "flag", "{", "}")):
            return val, name, "raw"
    return "", "", ""

def double_jpeg(path):
    if path.suffix.lower() not in (".jpg", ".jpeg"):
        return False
    data = path.read_bytes()
    return data.count(b"\xff\xdb") >= 3

def scan_image(path):
    tags = {}
    with path.open("rb") as f:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            tags = exifread.process_file(f, details=False)

    pillow_info = {}
    with Image.open(path) as im:
        pillow_info = im.info or {}

    # Extract metadata fields
    gps_lat = gps_to_decimal(tags.get("GPS GPSLatitude"), get_tag(tags, "GPS GPSLatitudeRef"))
    gps_lon = gps_to_decimal(tags.get("GPS GPSLongitude"), get_tag(tags, "GPS GPSLongitudeRef"))

    dt_original = get_tag(tags, "EXIF DateTimeOriginal")
    create_date = get_tag(tags, "EXIF DateTimeDigitized")
    modify_date = get_tag(tags, "Image DateTime")
    make = get_tag(tags, "Image Make")
    model = get_tag(tags, "Image Model")
    software = get_tag(tags, "Image Software") or str(pillow_info.get("Software", "")).strip()
    user_comment = get_tag(tags, "EXIF UserComment")
    image_desc = (
        get_tag(tags, "Image ImageDescription")
        or str(pillow_info.get("Description", "")).strip()
        or str(pillow_info.get("Comment", "")).strip()
    )

    # Covert channel detection
    covert_fields = {
        "Software": software,
        "UserComment": user_comment,
        "ImageDescription": image_desc,
        "Copyright": get_tag(tags, "Image Copyright"),
        "MakerNote": get_tag(tags, "EXIF MakerNote"),
    }
    secret_text, secret_field, secret_mode = find_secret(covert_fields)

    # Check for timestamp anomalies
    st = path.stat()
    fs_modified = datetime.fromtimestamp(st.st_mtime)
    ts_anomaly = False
    exif_time_str = dt_original or create_date or modify_date
    if exif_time_str:
        try:
            exif_dt = datetime.strptime(exif_time_str, "%Y:%m:%d %H:%M:%S")
            if abs((fs_modified - exif_dt).total_seconds()) > 60:
                ts_anomaly = True
        except ValueError:
            pass

    # Check for editing software 
    editing = any(hint in software.lower() for hint in EDITING_HINTS)
    dj = double_jpeg(path)

    # Give it a risk score based on findings
    risk = 0
    if secret_text:
        risk += 10
    if gps_lat or gps_lon:
        risk += 5
    if ts_anomaly:
        risk += 5
    if editing or dj:
        risk += 5

    return {
        "file": path.name,
        "GPSLatitude": gps_lat,
        "GPSLongitude": gps_lon,
        "DateTimeOriginal": dt_original,
        "CreateDate": create_date,
        "ModifyDate": modify_date,
        "Make": make,
        "Model": model,
        "Software": software,
        "UserComment": user_comment,
        "ImageDescription": image_desc,
        "FS_Modified": fs_modified.strftime("%Y-%m-%d %H:%M:%S"),
        "Timestamp_Anomaly": "YES" if ts_anomaly else "NO",
        "Editing_Software": "YES" if editing else "NO",
        "Double_JPEG": "YES" if dj else "NO",
        "Secret_Field": secret_field,
        "Secret_Mode": secret_mode,
        "Secret_Text": secret_text,
        "Risk_Score": risk,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python metadata_scanner.py <images_dir> [output.csv]")
        return

    images_dir = Path(sys.argv[1])
    out_csv = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path("metadata_report.csv")

    # Get all supported images
    images = sorted(
        [p for p in images_dir.rglob("*") if p.suffix.lower() in EXTENSIONS],
        key=lambda p: p.name.lower()
    )

    if not images:
        print("No images found.")
        return

    headers = [
        "file", "GPSLatitude", "GPSLongitude", "DateTimeOriginal", "CreateDate",
        "ModifyDate", "Make", "Model", "Software", "UserComment", "ImageDescription",
        "FS_Modified", "Timestamp_Anomaly", "Editing_Software", "Double_JPEG",
        "Secret_Field", "Secret_Mode", "Secret_Text", "Risk_Score",
    ]

    rows = []
    for p in images:
        try:
            row = scan_image(p)
            rows.append(row)
            print(f"  {row['file']}  risk={row['Risk_Score']}  secret_field={row['Secret_Field']}")
        except Exception as e:
            print(f"  ERROR {p.name}: {e}")

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} rows -> {out_csv}")

    # Detected secrets summary
    secrets = [(r["file"], r["Secret_Field"], r["Secret_Text"]) for r in rows if r["Secret_Text"]]
    if secrets:
        print("\n--- Secret Fragments ---")
        for fname, field, text in secrets:
            print(f"  [{fname}] {field}: {text}")
        print("\nReconstructed: " + " | ".join(t for _, _, t in secrets))


if __name__ == "__main__":
    main()