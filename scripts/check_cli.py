#!/usr/bin/env python3
"""End-to-end checks and five-run wall-clock CLI timings; raw synthetic RGB."""
import argparse,json,os,subprocess,tempfile,time,statistics,platform,hashlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--legacy',action='store_true');x=p.parse_args();binary=x.binary.resolve()
with tempfile.TemporaryDirectory() as temp:
 d=Path(temp);(d/'key').write_bytes(bytes(range(32)));(d/'p').write_bytes(bytes(range(256))*48)
 def call(*args):return subprocess.run([str(binary),*map(str,args)],capture_output=True)
 def enc(target,w=64,h=64,c=3):return call('encrypt','--key',d/'key','--input',d/'p','--output',target,'--width',w,'--height',h,'--channels',c)
 assert enc(d/'c1').returncode==0;assert enc(d/'c2').returncode==0
 a=(d/'c1').read_bytes();b=(d/'c2').read_bytes();out={'platform':platform.platform(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'nonce_repeats':a[17:49]==b[17:49],'ciphertext_repeats':a==b}
 assert call('decrypt','--key',d/'key','--input',d/'c1','--output',d/'r').returncode==0
 out['roundtrip']=(d/'r').read_bytes()==(d/'p').read_bytes()
 (d/'extended').write_bytes(a+b'\0');out['extension_rejected']=call('verify','--key',d/'key','--input',d/'extended').returncode!=0
 out['metadata_mismatch_rejected']=enc(d/'bad',w=1,h=1,c=1).returncode!=0
 if not x.legacy:
  assert not out['nonce_repeats'];assert out['extension_rejected'];assert out['metadata_mismatch_rejected']
  out['benchmarks']=[]
  for w,h in [(64,64),(256,256),(512,512)]:
   (d/'p').write_bytes(bytes((i*7)%256 for i in range(w*h*3)));en=[];de=[]
   for run in range(5):
    target=d/f'bench-{w}-{run}';t=time.perf_counter();assert enc(target,w,h,3).returncode==0;en.append((time.perf_counter()-t)*1000)
    t=time.perf_counter();assert call('decrypt','--key',d/'key','--input',target,'--output',str(target)+'.raw').returncode==0;de.append((time.perf_counter()-t)*1000)
    assert Path(str(target)+'.raw').read_bytes()==(d/'p').read_bytes()
   out['benchmarks'].append({'width':w,'height':h,'encrypt_ms_mean':statistics.mean(en),'encrypt_ms_sd':statistics.stdev(en),'decrypt_ms_mean':statistics.mean(de),'decrypt_ms_sd':statistics.stdev(de)})
 x.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
