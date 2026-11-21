#!/usr/bin/env python3
"""Encrypt and recover decoded image bytes using the experimental LRZIMG02 CLI."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', required=True, type=Path)
    p.add_argument('--output-dir', required=True, type=Path,
                   help='new directory, containing a demo key and recovered pixels')
    p.add_argument('--mode', choices=['L', 'LA', 'RGB', 'RGBA'],
                   help='optional explicit pixel conversion')
    p.add_argument('--binary', type=Path,
                   default=ROOT / 'code/target/release' / ('lrz.exe' if os.name == 'nt' else 'lrz'))
    a = p.parse_args()
    binary = a.binary.resolve()
    if not binary.is_file():
        p.error('build the release binary first (bash scripts/run.sh build)')
    with Image.open(a.input) as source:
        mode = a.mode or source.mode
        if mode not in ('L', 'LA', 'RGB', 'RGBA'):
            p.error('select --mode L, LA, RGB or RGBA for this input format')
        w, h = source.size
        channels = len(mode)
        if not w or not h or w * h * channels > 256 * 1024 * 1024:
            p.error('decoded image exceeds the 256 MiB payload limit')
        plain = source.convert(mode).tobytes()
    a.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = a.output_dir / 'demo.key'
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(os.urandom(32))
    key = key.resolve()
    encrypted = (a.output_dir / 'cipher.lrz').resolve()
    with tempfile.TemporaryDirectory() as temp:
        raw = Path(temp) / 'input.raw'
        recovered = Path(temp) / 'recovered.raw'
        raw.write_bytes(plain)
        subprocess.run([str(binary), 'encrypt', '--key', str(key), '--input', str(raw),
                        '--output', str(encrypted), '--width', str(w), '--height', str(h),
                        '--channels', str(channels)], check=True)
        subprocess.run([str(binary), 'decrypt', '--key', str(key), '--input', str(encrypted),
                        '--output', str(recovered)], check=True)
        result = recovered.read_bytes()
        if result != plain:
            raise RuntimeError('decoded-byte recovery failed')
    Image.frombytes(mode, (w, h), result).save(a.output_dir / 'recovered.png')
    print(f'PASS: {w}x{h} {mode}; {len(plain)} decoded bytes recovered exactly.')
    print(f'Demo files: {a.output_dir.resolve()} (includes a test key).')
    print('Research demonstration; PNG metadata and source file bytes are not preserved.')


if __name__ == '__main__':
    main()
