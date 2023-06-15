"""Standard-library research engine: return forecasts, chronological evaluation,
descriptive macro comparisons, event windows, and joint block-bootstrap scenarios.
No random market prices or fallback performance results are generated.
"""
import argparse
import bisect
import csv
import datetime as dt
import json
import math
import random
import re
import statistics as st
from pathlib import Path


def validate_coins(coins):
    if not coins or len(set(coins))!=len(coins):
        raise ValueError('Choose at least one unique coin symbol')
    if any(not isinstance(c,str) or not re.fullmatch(r'[A-Z0-9][A-Z0-9_-]{0,19}',c) or c in ('GOLD','M2') for c in coins):
        raise ValueError('Coin symbols must be safe uppercase identifiers; GOLD and M2 are reserved')


def user_holdings(prices,date,path):
    document=json.loads(Path(path).read_text(encoding='utf-8'))
    positions=document.get('positions',{})
    if set(positions)!=set(prices):
        raise ValueError('Portfolio positions must match config coins exactly; run setup_portfolio.py')
    result={}
    for coin,position in positions.items():
        if not isinstance(position,dict) or set(position) not in ({'units'},{'value_usd'}):
            raise ValueError(f'{coin}: provide exactly one of units or value_usd')
        key=next(iter(position))
        value=position[key]
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<=0:
            raise ValueError(f'{coin}: amount must be a finite positive number')
        price=prices[coin][date]
        units=value if key=='units' else value/price
        result[coin]={'units':units,'allocation_usd':units*price,'input_type':key,'input_amount':value}
    total=sum(v['allocation_usd'] for v in result.values())
    for position in result.values():
        position['weight']=position['allocation_usd']/total
    return result


def read_series(path, field='close'):
    result = {}
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        for row in csv.DictReader(f):
            date = dt.date.fromisoformat(row['date'])
            value = float(row[field])
            if not math.isfinite(value) or value <= 0 or date in result:
                raise ValueError(f'Invalid/nonpositive/duplicate observation: {path} {date}')
            result[date] = value
    if not result:
        raise ValueError(f'Empty input: {path}')
    return dict(sorted(result.items()))


def write_csv(path, rows):
    if not rows:
        return
    with Path(path).open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def asof(series, date, max_age):
    # Small macro/benchmark series; caller can cache if scaling up.
    dates = list(series)
    index = bisect.bisect_right(dates, date) - 1
    if index < 0 or (date - dates[index]).days > max_age:
        return None
    return series[dates[index]]


def price_features(prices, date):
    values = [prices.get(date - dt.timedelta(days=k)) for k in range(31)]
    if any(v is None for v in values):
        return None
    daily = [math.log(values[k] / values[k+1]) for k in range(30)]
    return [daily[0], math.log(values[0]/values[7]),
            math.log(values[0]/values[30]), st.pstdev(daily[:7]),
            st.pstdev(daily), values[0]/st.mean(values[:7])-1]


def macro_features(gold, m2, date, delay):
    # Gold must predate the crypto forecast origin by at least one date.
    yesterday = date - dt.timedelta(days=1)
    g0 = asof(gold, yesterday, 5)
    g7 = asof(gold, yesterday-dt.timedelta(days=7), 5)
    g30 = asof(gold, yesterday-dt.timedelta(days=30), 5)
    mdate = date - dt.timedelta(days=delay)
    m0 = asof(m2, mdate, 45)
    m90 = asof(m2, mdate-dt.timedelta(days=90), 45)
    if None in (g0, g7, g30, m0, m90):
        return None
    return [math.log(g0/g7), math.log(g0/g30), math.log(m0/m90)]


def samples(prices, gold=None, m2=None, delay=60):
    rows = []
    for date, price in prices.items():
        features = price_features(prices, date)
        target_date = date + dt.timedelta(days=1)
        if features is None or target_date not in prices:
            continue
        if gold is not None:
            macro = macro_features(gold, m2, date, delay)
            if macro is None:
                continue
            features += macro
        rows.append({'date': date, 'target_date': target_date, 'x': features,
                     'y': math.log(prices[target_date]/price), 'price': price,
                     'actual': prices[target_date]})
    return rows


def solve(matrix, vector):
    a = [list(row)+[value] for row, value in zip(matrix, vector)]
    n = len(a)
    for col in range(n):
        pivot = max(range(col, n), key=lambda row: abs(a[row][col]))
        a[col], a[pivot] = a[pivot], a[col]
        divisor = a[col][col]
        if abs(divisor) < 1e-12:
            raise ValueError('Singular system')
        a[col] = [v/divisor for v in a[col]]
        for row in range(n):
            if row != col:
                factor = a[row][col]
                a[row] = [x-factor*y for x,y in zip(a[row], a[col])]
    return [row[-1] for row in a]


def fit(rows, alpha):
    if alpha <= 0:
        raise ValueError('Ridge alpha must be positive')
    cols = list(zip(*(r['x'] for r in rows)))
    means = [st.mean(col) for col in cols]
    scales = [st.pstdev(col) or 1.0 for col in cols]
    center = st.mean(r['y'] for r in rows)
    z = [[(v-m)/s for v,m,s in zip(r['x'], means, scales)] for r in rows]
    n = len(means)
    matrix = [[sum(row[i]*row[j] for row in z)+(alpha if i==j else 0)
               for j in range(n)] for i in range(n)]
    vector = [sum(row[i]*(r['y']-center) for row,r in zip(z,rows)) for i in range(n)]
    return means, scales, center, solve(matrix,vector)


def predict(model, features):
    means, scales, center, weights = model
    return center + sum(w*(v-m)/s for w,v,m,s in zip(weights,features,means,scales))


def backtest(rows, cfg):
    if len(rows) <= cfg['train_min']:
        raise ValueError('Insufficient contiguous history for training and holdout')
    first = max(cfg['train_min'], len(rows)-cfg['test_days'])
    model = None
    results = []
    for index in range(first,len(rows)):
        row = rows[index]
        # Only labels already observed by the origin close can enter training.
        train = [r for r in rows[:index] if r['target_date'] <= row['date']]
        if model is None or (index-first) % cfg['refit_days'] == 0:
            model = fit(train, cfg['ridge_alpha'])
        prediction = predict(model,row['x'])
        results.append({'origin': row['date'].isoformat(),
                        'date': row['target_date'].isoformat(),
                        'origin_price': row['price'], 'actual_price': row['actual'],
                        'actual_return': row['y'], 'model_return': prediction,
                        'zero_return': 0.0,
                        'mean_return': st.mean(r['y'] for r in train)})
    return results


def metrics(results, column):
    actual = [r['actual_return'] for r in results]
    predicted = [r[column] for r in results]
    price_errors = [abs(r['origin_price']*math.exp(p)-r['actual_price'])
                    for r,p in zip(results,predicted)]
    return {'n': len(results),
            'return_mae': st.mean(abs(a-p) for a,p in zip(actual,predicted)),
            'return_rmse': math.sqrt(st.mean((a-p)**2 for a,p in zip(actual,predicted))),
            'price_mae_usd': st.mean(price_errors),
            'direction_accuracy': st.mean((a>0)==(p>0) for a,p in zip(actual,predicted)),
            'start': results[0]['date'], 'end': results[-1]['date']}


def correlation(pairs):
    if len(pairs)<3:
        return None
    x,y=zip(*pairs)
    if st.pstdev(x)==0 or st.pstdev(y)==0:
        return None
    return st.correlation(x,y)


def monthly(prices):
    grouped={}
    for date,value in prices.items():
        grouped[(date.year,date.month)] = (date,value)
    keys=sorted(grouped)
    result={}
    for previous,current in zip(keys,keys[1:]):
        if current[0]*12+current[1] - (previous[0]*12+previous[1]) == 1:
            result[current] = math.log(grouped[current][1]/grouped[previous][1])
    return result


def month_shift(key, months):
    number=key[0]*12+key[1]-1+months
    return number//12,number%12+1


def macro_comparison(all_prices,gold,m2):
    gold_returns=monthly(gold)
    m2_changes=monthly(m2)
    rows=[]
    for coin,prices in all_prices.items():
        returns=monthly(prices)
        for name,other,lags in [('GLD_adjusted_returns',gold_returns,[0]),
                                ('US_M2_monthly_growth',m2_changes,[0,1,2,3,6])]:
            for lag in lags:
                pairs=[(value,other[month_shift(key,-lag)]) for key,value in returns.items()
                       if month_shift(key,-lag) in other]
                rows.append({'coin':coin,'comparison':name,'lag_months':lag,
                             'n_months':len(pairs),'pearson':correlation(pairs),
                             'interpretation':'descriptive_latest_vintage_not_causal'})
    return rows


def event_windows(all_prices,event_file):
    output=[]
    with Path(event_file).open(encoding='utf-8',newline='') as f:
        for event in csv.DictReader(f):
            date=dt.date.fromisoformat(event['date'])
            for coin,prices in all_prices.items():
                base=prices.get(date-dt.timedelta(days=1))
                for horizon in (0,1,7):
                    end=prices.get(date+dt.timedelta(days=horizon))
                    if base is not None and end is not None:
                        output.append({'event':event['event'],'date':event['date'],
                            'coin':coin,'end_offset_days':horizon,
                            'return_from_prior_close':end/base-1,'source':event['source'],
                            'warning':'raw_event_window_not_causal_or_trade_signal'})
    return output


def random_holdings(prices, date, budget, seed):
    rng=random.Random(seed)
    weights={coin: math.exp(rng.uniform(-2,2)) for coin in sorted(prices)}
    total=sum(weights.values())
    return {coin: {'weight':weights[coin]/total,
                   'allocation_usd':budget*weights[coin]/total,
                   'units':budget*weights[coin]/total/prices[coin][date]}
            for coin in sorted(prices)}


def percentile(values,q):
    values=sorted(values)
    index=(len(values)-1)*q
    lo=int(index)
    hi=min(lo+1,len(values)-1)
    return values[lo]+(values[hi]-values[lo])*(index-lo)


def scenarios(prices,date,holdings,cfg,coin_summaries=False):
    # Joint date sampling preserves cross-coin co-movement; contiguous blocks
    # preserve some short-run dependence. Not a learned 1-year price forecast.
    coins=sorted(prices)
    common=sorted(set.intersection(*(set(p) for p in prices.values())))
    common=[d for d in common if d<=date and d-dt.timedelta(days=1) in common]
    valid=set(common)
    block=cfg['scenario_block_days']
    starts=[d for d in common if all(d+dt.timedelta(days=k) in valid for k in range(block))]
    if not starts:
        raise ValueError('No contiguous common blocks for joint scenarios')
    rng=random.Random(cfg['scenario_seed'])
    distributions=[[] for _ in range(cfg['scenario_days']+1)]
    snapshots={}
    for _ in range(cfg['scenario_paths']):
        values={c:holdings[c]['units']*prices[c][date] for c in coins}
        distributions[0].append(sum(values.values()))
        day=0
        while day<cfg['scenario_days']:
            start=rng.choice(starts)
            for k in range(block):
                if day>=cfg['scenario_days']:
                    break
                d=start+dt.timedelta(days=k)
                for coin in coins:
                    values[coin] *= prices[coin][d]/prices[coin][d-dt.timedelta(days=1)]
                day+=1
                distributions[day].append(sum(values.values()))
                future=date+dt.timedelta(days=day)
                if coin_summaries and ((future.month,future.day)==(12,31) or day==cfg['scenario_days']):
                    for coin in coins:
                        snapshots.setdefault((str(future),coin),[]).append(values[coin]/holdings[coin]['units'])
    aggregate=[{'day':i,'date':(date+dt.timedelta(days=i)).isoformat(),
             'p05':percentile(v,.05),'median':percentile(v,.5),'p95':percentile(v,.95)}
            for i,v in enumerate(distributions)]
    if coin_summaries:
        summary=[{'date':date,'coin':coin,'price_p05_usd':percentile(v,.05),
                  'price_median_usd':percentile(v,.5),'price_p95_usd':percentile(v,.95),
                  'method':'historical_block_bootstrap_not_calibrated_prediction'}
                 for (date,coin),v in sorted(snapshots.items())]
        return aggregate,summary
    return aggregate


def chart_svg(path, rows, fields):
    values=[float(r[f]) for r in rows for f in fields]
    low,high=min(values),max(values)
    span=high-low or 1
    colors=['#3269c8','#c0392b','#28864a']
    parts=['<svg xmlns="http://www.w3.org/2000/svg" width="900" height="400" viewBox="0 0 900 400">',
           '<rect width="900" height="400" fill="white"/>',
           f'<text x="30" y="25">Range: {low:.4g} to {high:.4g}; x = observation order</text>']
    for field,color in zip(fields,colors):
        points=' '.join(f'{30+i*830/max(1,len(rows)-1):.2f},{350-(float(r[field])-low)*290/span:.2f}'
                        for i,r in enumerate(rows))
        parts.append(f'<polyline fill="none" stroke="{color}" points="{points}"/>')
        parts.append(f'<text x="{30+fields.index(field)*270}" y="385" fill="{color}">{field}</text>')
    parts.append('</svg>')
    Path(path).write_text('\n'.join(parts),encoding='utf-8')


def run(args):
    cfg=json.loads(Path(args.config).read_text())
    validate_coins(cfg['coins'])
    for key in ('train_min','test_days','refit_days','scenario_days','scenario_paths','scenario_block_days'):
        if cfg[key]<1:
            raise ValueError(f'{key} must be positive')
    data,out=Path(args.data),Path(args.output)
    out.mkdir(parents=True,exist_ok=True)
    prices={c:read_series(data/(c+'.csv')) for c in cfg['coins']}
    # Refuse a silent partial download or silently shortened coin universe.
    gold=read_series(data/'GOLD.csv')
    m2=read_series(data/'M2.csv','value')
    summaries=[]
    all_backtests={}
    next_day=[]
    date=min(max(p) for p in prices.values())
    if any((max(p)-date).days>1 for p in prices.values()):
        raise ValueError('Coin histories end on inconsistent dates')
    if any(date not in p for p in prices.values()):
        raise ValueError('Missing common portfolio valuation close')
    for coin,p in prices.items():
        all_backtests[coin]={}
        sets={'price_only':samples(p)}
        if args.exploratory_macro:
            augmented=samples(p,gold,m2,cfg['m2_exploratory_delay_days'])
            eligible={r['date'] for r in augmented}
            sets={'price_only_matched': [r for r in sets['price_only'] if r['date'] in eligible],
                  'macro_exploratory_revised':augmented}
        for label,rows in sets.items():
            results=backtest(rows,cfg)
            all_backtests[coin][label]=results
            write_csv(out/f'{coin}_{label}_backtest.csv',results)
            for column in ('model_return','zero_return','mean_return'):
                summaries.append({'coin':coin,'features':label,'model':column,**metrics(results,column)})
            chart_svg(out/f'{coin}_{label}.svg',results,['actual_return','model_return'])
        train=[r for r in samples(p) if r['target_date']<=date]
        features=price_features(p,date)
        if features is None:
            raise ValueError(f'Missing contiguous recent prices for {coin}')
        model=fit(train,cfg['ridge_alpha'])
        ret=predict(model,features)
        next_day.append({'coin':coin,'origin':date.isoformat(),
                         'date':(date+dt.timedelta(days=1)).isoformat(),
                         'origin_price':p[date], 'predicted_log_return':ret,
                         'forecast_price':p[date]*math.exp(ret)})
    portfolio_file=getattr(args,'portfolio',None) or cfg.get('portfolio_file')
    if portfolio_file:
        portfolio_path=Path(portfolio_file)
        if not portfolio_path.is_absolute():
            portfolio_path=Path(args.config).resolve().parent/portfolio_path
        holdings=user_holdings(prices,date,portfolio_path)
    else:
        holdings=random_holdings(prices,date,cfg['portfolio_budget_usd'],cfg['portfolio_seed'])
    portfolio_label='User-supplied positions' if portfolio_file else 'Randomized example positions'
    actual_budget=sum(v['allocation_usd'] for v in holdings.values())
    write_csv(out/'portfolio_holdings.csv',[{'coin':c,'valuation_date':date.isoformat(),**v} for c,v in holdings.items()])
    if not portfolio_file:
        write_csv(out/'example_holdings.csv',[{'coin':c,'valuation_date':date.isoformat(),**v} for c,v in holdings.items()])
    write_csv(out/'backtest_metrics.csv',summaries)
    write_csv(out/'next_day_forecasts.csv',next_day)
    write_csv(out/'macro_correlations.csv',macro_comparison(prices,gold,m2))
    write_csv(out/'event_windows.csv',event_windows(prices,args.events))
    paths=scenarios(prices,date,holdings,cfg)
    write_csv(out/'portfolio_1year_scenarios.csv',paths)
    chart_svg(out/'portfolio_scenarios.svg',paths,['p05','median','p95'])
    long_end=dt.date.fromisoformat(cfg.get('long_term_end','2030-12-31'))
    if long_end<=date:
        raise ValueError('long_term_end must be after the input valuation date')
    long_paths,coin_yearends=scenarios(prices,date,holdings,{**cfg,'scenario_days':(long_end-date).days},coin_summaries=True)
    write_csv(out/'coin_price_scenarios_yearends.csv',coin_yearends)
    write_csv(out/'portfolio_scenarios_2030.csv',long_paths)
    chart_svg(out/'portfolio_scenarios_2030.svg',long_paths,['p05','median','p95'])
    import charts
    charts.report(prices,gold,m2,holdings,all_backtests,summaries,paths,long_paths,out,
                  synthetic=getattr(args,'synthetic_test_data',False),coin_yearends=coin_yearends,
                  portfolio_label=portfolio_label)
    forecast=sum(holdings[r['coin']]['units']*r['forecast_price'] for r in next_day)
    (out/'portfolio_next_day.json').write_text(json.dumps({'valuation_date':str(date),
        'current_usd':actual_budget,'forecast_usd':forecast,
        'portfolio':portfolio_label},indent=2))
    (out/'run_manifest.json').write_text(json.dumps({'completed_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
        'config':cfg,'macro_mode':args.exploratory_macro,
        'macro_warning':'Latest revised M2 with assumed delay is not a point-in-time tradable backtest',
        'annual_output':'joint historical block-bootstrap scenario distribution, not calibrated confidence interval',
        'data_provenance':'see input data/manifest.json'},indent=2))
    print(f'Completed study. Metrics and scenarios: {out.resolve()}')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',default='config.json')
    parser.add_argument('--data',default='data')
    parser.add_argument('--events',default='events.csv')
    parser.add_argument('--output',default='results')
    parser.add_argument('--exploratory-macro',action='store_true')
    parser.add_argument('--synthetic-test-data',action='store_true',help='Label reports from software fixtures; never use as market evidence')
    run(parser.parse_args())
