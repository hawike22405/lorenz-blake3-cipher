#!/usr/bin/env python3
import subprocess,sys,tempfile
from pathlib import Path
script=Path(__file__).with_name('aead_file.py')
with tempfile.TemporaryDirectory() as t:
 p=Path(t);(p/'plain').write_bytes(b'example file\x00'*100)
 def run(op,*args):return subprocess.run([sys.executable,str(script),op,*map(str,args)],capture_output=True)
 assert run('keygen','--key',p/'key').returncode==0
 assert run('encrypt','--key',p/'key','--input',p/'plain','--output',p/'enc').returncode==0
 assert run('decrypt','--key',p/'key','--input',p/'enc','--output',p/'dec').returncode==0
 assert (p/'plain').read_bytes()==(p/'dec').read_bytes()
 b=bytearray((p/'enc').read_bytes());b[-1]^=1;(p/'bad').write_bytes(b)
 assert run('decrypt','--key',p/'key','--input',p/'bad','--output',p/'leak').returncode!=0
 assert not (p/'leak').exists()
 assert run('keygen','--key',p/'key').returncode!=0
 print('AES-GCM wrapper: exact file recovery, tamper rejection without output, no key overwrite: PASS')
