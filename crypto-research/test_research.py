"""Synthetic fixtures test software behavior, never investment performance."""
import argparse
import csv
import datetime as dt
import json
import math
from pathlib import Path
import tempfile
import unittest
import research as r


def fixture(days=500, scale=100):
    start=dt.date(2023,1,1)
    return {start+dt.timedelta(days=i): scale*math.exp(.0003*i+.08*math.sin(i/13))
            for i in range(days)}


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.cfg={'train_min':120,'test_days':40,'refit_days':10,'ridge_alpha':10,
                  'scenario_seed':5,'scenario_paths':20,'scenario_days':30,
                  'scenario_block_days':7}

    def test_target_is_tomorrow(self):
        p=fixture()
        row=r.samples(p)[0]
        self.assertEqual(row['target_date']-row['date'],dt.timedelta(days=1))
        self.assertAlmostEqual(row['y'],math.log(p[row['target_date']]/p[row['date']]))

    def test_future_prices_do_not_change_first_prediction(self):
        p=fixture()
        original=r.backtest(r.samples(p),self.cfg)
        cutoff=dt.date.fromisoformat(original[0]['origin'])
        altered={d:v*(3 if d>cutoff else 1) for d,v in p.items()}
        changed=r.backtest(r.samples(altered),self.cfg)
        self.assertAlmostEqual(original[0]['model_return'],changed[0]['model_return'])
        self.assertNotEqual(original[0]['actual_return'],changed[0]['actual_return'])

    def test_scaling_fits_training_only(self):
        rows=[{'x':[float(i),1.0], 'y':float(i)*2} for i in range(20)]
        model=r.fit(rows,1)
        self.assertEqual(model[0],[9.5,1.0])
        self.assertTrue(math.isfinite(r.predict(model,[10000,1])))

    def test_macro_uses_prior_gold_and_delayed_m2(self):
        d=dt.date(2024,6,30)
        gold=fixture(600)
        m2={dt.date(2023+i//12,i%12+1,1):100+i for i in range(24)}
        first=r.macro_features(gold,m2,d,60)
        future_gold={date:value*(9 if date>=d else 1) for date,value in gold.items()}
        future_m2={date:value*(4 if date>d-dt.timedelta(days=60) else 1)
                   for date,value in m2.items()}
        self.assertEqual(first,r.macro_features(future_gold,future_m2,d,60))
        self.assertIsNone(r.asof(gold,dt.date(2030,1,1),5))

    def test_holdings_are_reproducible_and_budget_balanced(self):
        p={'A':fixture(),'B':fixture(scale=2)}
        date=max(p['A'])
        a=r.random_holdings(p,date,10000,42)
        self.assertEqual(a,r.random_holdings(p,date,10000,42))
        self.assertNotEqual(a,r.random_holdings(p,date,10000,99))
        self.assertAlmostEqual(sum(v['units']*p[c][date] for c,v in a.items()),10000)

    def test_joint_scenarios_preserve_identical_return_streams(self):
        p={'A':fixture(),'B':fixture(scale=2)}
        date=max(p['A'])
        h=r.random_holdings(p,date,10000,42)
        result=r.scenarios(p,date,h,self.cfg)
        only=r.scenarios({'A':p['A']},date,{'A':{'units':10000/p['A'][date]}},self.cfg)
        self.assertEqual(len(result),31)
        self.assertAlmostEqual(result[-1]['median'],only[-1]['median'])
        self.assertTrue(all(row['p05']<=row['median']<=row['p95'] for row in result))

    def test_missing_days_are_not_forward_filled(self):
        p=fixture()
        missing=min(p)+dt.timedelta(days=200)
        del p[missing]
        self.assertTrue(all(row['date']!=missing-dt.timedelta(days=1) for row in r.samples(p)))
        self.assertIsNone(r.price_features(p,missing+dt.timedelta(days=10)))

    def test_duplicate_dates_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path=Path(temp)/'bad.csv'
            path.write_text('date,close\n2024-01-01,1\n2024-01-01,2\n')
            with self.assertRaises(ValueError):
                r.read_series(path)

    def test_full_pipeline_both_modes(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            base=Path(temp)
            p=fixture(800)
            for coin,scale in [('A',1),('B',2),('GOLD',.5)]:
                r.write_csv(base/(coin+'.csv'),[{'date':str(d),'close':v*scale} for d,v in p.items()])
            months=[]
            for year in (2022,2023,2024,2025):
                for month in range(1,13):
                    months.append({'date':f'{year}-{month:02d}-01','value':100+len(months)})
            r.write_csv(base/'M2.csv',months)
            cfg={**self.cfg,'coins':['A','B'],'portfolio_budget_usd':10000,
                 'portfolio_seed':42,'m2_exploratory_delay_days':60}
            (base/'config.json').write_text(json.dumps(cfg))
            (base/'events.csv').write_text('date,event,category,source\n2024-01-10,fixture,test,fixture-only\n')
            for macro in (False,True):
                if macro:
                    (base/'custom.json').write_text(json.dumps({'positions':{'A':{'units':2},'B':{'value_usd':250}}}))
                    cfg['portfolio_file']='custom.json'
                    (base/'config.json').write_text(json.dumps(cfg))
                output=base/('macro' if macro else 'price')
                r.run(argparse.Namespace(config=str(base/'config.json'),data=str(base),
                    output=str(output),events=str(base/'events.csv'),exploratory_macro=macro))
                for name in ('backtest_metrics.csv','event_windows.csv','macro_correlations.csv',
                             'portfolio_holdings.csv','portfolio_1year_scenarios.csv',
                             'next_day_forecasts.csv','portfolio_next_day.json','portfolio_scenarios.svg',
                             'report.html','coin_price_scenarios_yearends.csv','portfolio_scenarios_2030.csv'):
                    self.assertTrue((output/name).stat().st_size>0,name)
                with (output/'backtest_metrics.csv').open() as f:
                    self.assertEqual(len(list(csv.DictReader(f))),12 if macro else 6)
                if macro:
                    actual=json.loads((output/'portfolio_next_day.json').read_text())
                    self.assertAlmostEqual(actual['current_usd'],p[max(p)]*2+250)
                    self.assertEqual(actual['portfolio'],'User-supplied positions')

    def test_technical_range_excludes_today_and_drawdown(self):
        import charts
        p=fixture(250)
        last=max(p)
        p[last]=max(p.values())*2
        result=charts.technicals(p)
        self.assertEqual(result[-1]['range_status'],'above_prior_range')
        self.assertLess(result[-1]['prior_30_close_resistance'],p[last])
        self.assertEqual(result[-1]['drawdown'],0)
        self.assertGreaterEqual(result[-1]['rsi14_wilder'],0)
        self.assertLessEqual(result[-1]['rsi14_wilder'],100)

    def test_yearend_coin_scenarios(self):
        p={'A':fixture(360)}
        date=max(p['A'])
        h=r.random_holdings(p,date,10000,42)
        aggregate,annual=r.scenarios(p,date,h,{**self.cfg,'scenario_days':15},coin_summaries=True)
        self.assertEqual(annual[-1]['date'],str(date+dt.timedelta(days=15)))
        self.assertTrue(all(row['price_p05_usd']<=row['price_median_usd']<=row['price_p95_usd'] for row in annual))

    def test_custom_quantities_and_usd_values(self):
        p={'BTC':fixture(),'ETH':fixture(scale=5)}
        date=max(p['BTC'])
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path=Path(temp)/'portfolio.json'
            path.write_text(json.dumps({'positions':{'BTC':{'units':.25},'ETH':{'value_usd':300}}}))
            h=r.user_holdings(p,date,path)
            self.assertEqual(h['BTC']['units'],.25)
            self.assertAlmostEqual(h['ETH']['allocation_usd'],300)
            self.assertAlmostEqual(sum(v['weight'] for v in h.values()),1)
            path.write_text(json.dumps({'positions':{'BTC':{'units':-1},'ETH':{'value_usd':300}}}))
            with self.assertRaises(ValueError): r.user_holdings(p,date,path)

    def test_unsafe_symbols_rejected(self):
        for symbols in ([],['BTC','BTC'],['../BTC'],['GOLD']):
            with self.assertRaises(ValueError): r.validate_coins(symbols)


if __name__=='__main__':
    unittest.main()
