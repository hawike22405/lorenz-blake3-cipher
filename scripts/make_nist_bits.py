#!/usr/bin/env python3
"""Prepare lrz ciphertext for the NIST SP 800-22 test suite (STS).

Strips the 81-byte header and 32-byte tag from each LRZIMG02 container,
concatenates the payloads and trims the result to whole 1,000,000-bit
streams. Prints the stream count to enter in `./assess`.

Usage:
    python3 scripts/make_nist_bits.py image.lrz
    python3 scripts/make_nist_bits.py a.lrz b.lrz c.lrz -o cipher_bits.bin
"""
import argparse
import struct
from pathlib import Path

HEADER, TAG = 81, 32
STREAM_BYTES = 125_000  # 1,000,000 bits


def payload(path: Path) -> bytes:
    blob = path.read_bytes()
    if len(blob) < HEADER + TAG or blob[:8] != b"LRZIMG02":
        raise SystemExit(f"{path}: not an LRZIMG02 container")
    width, height = struct.unpack("<II", blob[8:16])
    channels = blob[16]
    if len(blob) != HEADER + width * height * channels + TAG:
        raise SystemExit(f"{path}: length does not match header geometry")
    return blob[HEADER:-TAG]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("inputs", nargs="+", type=Path, help=".lrz container(s)")
    p.add_argument("-o", "--output", type=Path, default=Path("cipher_bits.bin"))
    a = p.parse_args()

    data = b"".join(payload(f) for f in a.inputs)
    streams = len(data) // STREAM_BYTES
    if streams == 0:
        raise SystemExit(f"need at least {STREAM_BYTES} payload bytes, got {len(data)}")
    try:
        with open(a.output, "xb") as f:  # never overwrite
            f.write(data[: streams * STREAM_BYTES])
    except FileExistsError:
        raise SystemExit(f"{a.output} already exists; choose another -o path or delete it")
    print(f"wrote {a.output} ({streams * STREAM_BYTES} bytes)")
    print(f"bitstreams to enter in ./assess: {streams}")


if __name__ == "__main__":
    main()
