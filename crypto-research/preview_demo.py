"""Generate an explicitly synthetic visual demo. Not a historical market study."""
import argparse
import datetime as dt
import json
import math
from pathlib import Path
import shutil
import tempfile
import research as r


def main():
    output=Path('preview.html').resolve()
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
        data=Path(folder)
        start=dt.date(2022,1,1)
        for index,coin in enumerate(['FIXTURE_A','FIXTURE_B','FIXTURE_C','GOLD']):
            rows=[]
            for i in range(1200):
                date=start+dt.timedelta(days=i)
                if coin=='GOLD' and date.weekday()>4:
                    continue
                value=(20+index*50)*math.exp(.0002*i+.2*math.sin(i/(21+index*8))+.04*math.sin(i/3))
                rows.append({'date':str(date),'close':value})
            r.write_csv(data/(coin+'.csv'),rows)
        r.write_csv(data/'M2.csv',[{'date':f'{year}-{month:02d}-01','value':19000+(year-2021)*500+month*30}
            for year in range(2021,2026) for month in range(1,13)])
        cfg=json.loads(Path('config.json').read_text())
        cfg.update(coins=['FIXTURE_A','FIXTURE_B','FIXTURE_C'],scenario_paths=40,test_days=180)
        (data/'config.json').write_text(json.dumps(cfg))
        r.run(argparse.Namespace(config=str(data/'config.json'),data=str(data),events='events.csv',
            output=str(data/'outputs'),exploratory_macro=False,synthetic_test_data=True))
        shutil.copyfile(data/'outputs'/'report.html',output)
    print('Synthetic visual demo written to',output)


if __name__=='__main__':
    main()
