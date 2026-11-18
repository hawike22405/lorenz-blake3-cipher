#!/usr/bin/env python3
"""Small AES-256-GCM file wrapper; separate format, never the research cipher."""
import argparse, os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
MAGIC = b'AESFILE1'
LIMIT = 64 * 1024 * 1024

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('operation', choices=['keygen','encrypt','decrypt'])
    a.add_argument('--key',required=True,type=Path)
    a.add_argument('--input',type=Path);a.add_argument('--output',type=Path)
    x=a.parse_args()
    if x.operation=='keygen':
        fd=os.open(x.key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(AESGCM.generate_key(bit_length=256))
        return
    if not x.input or not x.output:a.error('--input and --output are required')
    k=x.key.read_bytes()
    if len(k)!=32:a.error('key must be exactly 32 bytes')
    if x.input.stat().st_size>LIMIT+36:a.error('input exceeds 64 MiB policy')
    b=x.input.read_bytes()
    if x.operation=='encrypt':
        if len(b)>LIMIT:a.error('plaintext exceeds 64 MiB policy')
        header=MAGIC+os.urandom(12)
        out=header+AESGCM(k).encrypt(header[8:],b,header)
    else:
        if len(b)<36 or b[:8]!=MAGIC:a.error('invalid AESFILE1 container')
        out=AESGCM(k).decrypt(b[8:20],b[20:],b[:20])
    # No output exists until decryption authentication has succeeded; never overwrite.
    with x.output.open('xb') as f:f.write(out)
if __name__=='__main__':
    try:main()
    except Exception as e:
        raise SystemExit(f'operation failed: {type(e).__name__}: {e}')
