#!/usr/bin/env python3
import json,statistics
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'review/ablation.log').read_text();rows=json.loads(s.split('REVIEW_JSON_BEGIN')[1].split('REVIEW_JSON_END')[0])
(root/'review/ablation_trials.json').write_text(json.dumps(rows,indent=2)+'\n')
out=[]
for mode,name in enumerate(['full','zero_trajectory','no_diffusion','no_permutation','old_feedback']):
 r=[x for x in rows if x['mode']==mode];o={'mode':name,'n':len(r)}
 for k in ['npcr','uaci']:
  v=[x[k] for x in r];o[k+'_mean']=statistics.mean(v);o[k+'_sd']=statistics.stdev(v)
 out.append(o)
(root/'review/ablation_summary.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
