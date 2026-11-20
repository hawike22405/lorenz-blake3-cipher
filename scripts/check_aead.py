#!/usr/bin/env python3
"""Exercise file recovery, failure paths, overwrite policy and private modes."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

script = Path(__file__).with_name('aead_file.py')
with tempfile.TemporaryDirectory() as temp:
    p = Path(temp)
    (p / 'plain').write_bytes(b'example file\x00' * 100)

    def run(op, *args):
        return subprocess.run([sys.executable, str(script), op, *map(str, args)], capture_output=True)

    assert run('keygen', '--key', p / 'key').returncode == 0
    assert run('keygen', '--key', p / 'wrong').returncode == 0
    key_before = (p / 'key').read_bytes()
    assert run('keygen', '--key', p / 'key').returncode != 0
    assert (p / 'key').read_bytes() == key_before
    for name in ('enc', 'enc2'):
        assert run('encrypt', '--key', p / 'key', '--input', p / 'plain', '--output', p / name).returncode == 0
    container = (p / 'enc').read_bytes()
    assert container[8:20] != (p / 'enc2').read_bytes()[8:20]
    assert run('decrypt', '--key', p / 'key', '--input', p / 'enc', '--output', p / 'dec').returncode == 0
    assert (p / 'plain').read_bytes() == (p / 'dec').read_bytes()
    for label, changed in (
        ('tag', container[:-1] + bytes([container[-1] ^ 1])),
        ('nonce', container[:8] + bytes([container[8] ^ 1]) + container[9:]),
        ('header', bytes([container[0] ^ 1]) + container[1:]),
        ('truncated', container[:-1]),
        ('extended', container + b'\x00'),
    ):
        (p / 'bad').write_bytes(changed)
        assert run('decrypt', '--key', p / 'key', '--input', p / 'bad', '--output', p / 'leak').returncode != 0, label
        assert not (p / 'leak').exists(), label
    assert run('decrypt', '--key', p / 'wrong', '--input', p / 'enc', '--output', p / 'leak').returncode != 0
    assert not (p / 'leak').exists()
    assert run('decrypt', '--key', p / 'key', '--input', p / 'enc', '--output', p / 'dec').returncode != 0
    assert (p / 'plain').read_bytes() == (p / 'dec').read_bytes()
    if os.name == 'posix':
        for name in ('key', 'enc', 'dec'):
            assert stat.S_IMODE((p / name).stat().st_mode) == 0o600
    print('PASS: AES-GCM round trip, tested nonce difference, wrong key, 5 corruptions, no unauthenticated output, no overwrite, POSIX private files.')
