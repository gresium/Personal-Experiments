"""Self-contained HTML research report, SVG charts, and close-based technicals."""
import csv
import datetime as dt
import html
import math
import statistics as st
from pathlib import Path

COLORS=['#6da8ff','#42d9b3','#ffbf69','#bc9aff','#f483a0','#65d2e6','#e6da79','#a5c999','#d9b7ff','#ef9d74']


def esc(value):
    return html.escape(str(value),quote=True)


def svg(series, percent=False):
    # Each series is (name, [(ISO date, finite number), ...]). Dates share a real axis.
    series=[(n,points) for n,points in series if points]
    if not series:
        return '<p>No observations for this chart.</p>'
    dates=sorted({d for _,points in series for d,v in points})
    start,end=dt.date.fromisoformat(dates[0]),dt.date.fromisoformat(dates[-1])
    values=[v for _,points in series for d,v in points]
    low,high=min(values),max(values)
    pad=(high-low or max(abs(high),1))*.08
    low-=pad; high+=pad
    def x(date):
        return 85+870*(dt.date.fromisoformat(date)-start).days/max(1,(end-start).days)
    def y(value):
        return 285-(value-low)/(high-low)*245
    parts=['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 370" role="img">']
    for i in range(5):
        value=low+(high-low)*i/4
        label=f'{value:.1%}' if percent else f'{value:,.3g}'
        parts.append(f'<path d="M85 {y(value):.2f} H955" stroke="#293950"/>')
        parts.append(f'<text x="74" y="{y(value)+4:.2f}" text-anchor="end">{label}</text>')
    for i,(name,points) in enumerate(series):
        color=COLORS[i%len(COLORS)]
        coords=' '.join(f'{x(d):.2f},{y(v):.2f}' for d,v in points)
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="1.8" points="{coords}"/>')
        parts.append(f'<text x="{85+(i%4)*220}" y="{326+(i//4)*18}" fill="{color}">{esc(name)}</text>')
    parts += [f'<text x="85" y="307">{start}</text>',
              f'<text x="955" y="307" text-anchor="end">{end}</text>','</svg>']
    return ''.join(parts)


def technicals(prices):
    dates=list(prices)
    values=list(prices.values())
    peak=0
    avg_gain=avg_loss=None
    output=[]
    for i,(date,close) in enumerate(zip(dates,values)):
        peak=max(peak,close)
        contiguous= i>=200 and (date-dates[i-200]).days==200
        sma50=st.mean(values[i-49:i+1]) if i>=49 and (date-dates[i-49]).days==49 else None
        sma200=st.mean(values[i-199:i+1]) if i>=199 and (date-dates[i-199]).days==199 else None
        prior=values[i-30:i] if i>=30 and (date-dates[i-30]).days==30 else []
        ret=math.log(close/values[i-1]) if i and (date-dates[i-1]).days==1 else None
        if ret is None:
            avg_gain=avg_loss=None
        elif i>=14 and (date-dates[i-14]).days==14:
            if avg_gain is None:
                changes=[values[k]-values[k-1] for k in range(i-13,i+1)]
                avg_gain=st.mean(max(c,0) for c in changes)
                avg_loss=st.mean(max(-c,0) for c in changes)
            else:
                change=close-values[i-1]
                avg_gain=(13*avg_gain+max(change,0))/14
                avg_loss=(13*avg_loss+max(-change,0))/14
        rsi=None if avg_gain is None else (50 if avg_gain==avg_loss==0 else
             100 if avg_loss==0 else 100-100/(1+avg_gain/avg_loss))
        returns=[math.log(values[k]/values[k-1]) for k in range(max(1,i-29),i+1)]
        vol=st.pstdev(returns)*math.sqrt(365) if i>=30 and prior else None
        support=min(prior) if prior else None
        resistance=max(prior) if prior else None
        trend='insufficient_history'
        if sma50 is not None and sma200 is not None:
            trend='bullish_alignment' if close>sma50>sma200 else (
                  'bearish_alignment' if close<sma50<sma200 else 'mixed_alignment')
        output.append({'date':str(date),'close':close,'sma50':sma50,'sma200':sma200,
            'prior_30_close_support':support,'prior_30_close_resistance':resistance,
            'drawdown':close/peak-1,'annualized_volatility_30d':vol,'rsi14_wilder':rsi,
            'trend_label':trend,
            'range_status':'above_prior_range' if resistance and close>resistance else (
                'below_prior_range' if support and close<support else 'within_range' if prior else 'unknown')})
    return output


def table(headers,rows):
    return '<div class="scroll"><table><thead><tr>'+''.join('<th>'+esc(h)+'</th>' for h in headers)+\
        '</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+esc(v)+'</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table></div>'


def panel(title,body,note=''):
    return '<section class="panel"><h2>'+esc(title)+'</h2>'+('<p>'+esc(note)+'</p>' if note else '')+body+'</section>'


def report(prices,gold,m2,holdings,backtests,metrics,paths,long_paths,out,synthetic=False,coin_yearends=None,portfolio_label='Randomized example positions'):
    out=Path(out)
    coin_names=sorted(prices)
    common=sorted(set.intersection(*(set(p) for p in prices.values())))
    if not common:
        raise ValueError('No common dates for chart comparison')
    # Fair rebasing: same first/last common observations across all assets.
    normalized=[(c,[(str(d),prices[c][d]/prices[c][common[0]]*100) for d in common]) for c in coin_names]
    body=panel('Relative price performance — common period',svg(normalized),
        'Every coin starts at 100 on the same date. Fixed present-day asset selection creates survivorship bias.')
    rows=[]
    daily_returns={c:{d:math.log(v/p[d-dt.timedelta(days=1)]) for d,v in p.items()
                      if d-dt.timedelta(days=1) in p} for c,p in prices.items()}
    for a in coin_names:
        values=[]
        for b in coin_names:
            dates=sorted(set(daily_returns[a]) & set(daily_returns[b]))
            x=[daily_returns[a][d] for d in dates]
            y=[daily_returns[b][d] for d in dates]
            corr=st.correlation(x,y) if len(dates)>=3 and st.pstdev(x)>0 and st.pstdev(y)>0 else None
            values.append('n/a' if corr is None else f'{corr:.2f} (n={len(dates)})')
        rows.append([a]+values)
    body+=panel('Daily log-return correlations',table(['Coin']+coin_names,rows),
        'Pairwise overlapping dates; different cells can use different periods. Co-movement is not guaranteed diversification.')
    body+='<label class="selector">Inspect coin <select id="coin">'+''.join(f'<option>{esc(c)}</option>' for c in coin_names)+'</select></label>'
    for index,(coin,p) in enumerate(sorted(prices.items())):
        data=technicals(p)
        with (out/(coin+'_technicals.csv')).open('w',newline='',encoding='utf-8') as f:
            writer=csv.DictWriter(f,fieldnames=list(data[0]));writer.writeheader();writer.writerows(data)
        body+=f'<div class="coin" data-coin="{esc(coin)}"'+(' hidden' if index else '')+'>'
        latest=data[-1]
        body+=panel(coin+' — technical snapshot',table(['Field','Value'],[
            ['As of',latest['date']],['Close (USD)',f'{latest["close"]:,.4f}'],
            ['Trend heuristic',latest['trend_label']],['Prior 30-close range',latest['range_status']],
            ['RSI 14 (Wilder)','n/a' if latest['rsi14_wilder'] is None else f'{latest["rsi14_wilder"]:.1f}']]),
            'Heuristic labels describe the chart; they are not validated buy/sell recommendations.')
        fields=['close','sma50','sma200','prior_30_close_support','prior_30_close_resistance']
        labels=['Close USD','SMA 50','SMA 200','Prior 30-close low','Prior 30-close high']
        series=[(label,[(row['date'],row[field]) for row in data[-365:] if row[field] is not None]) for field,label in zip(fields,labels)]
        body+=panel(coin+' — price, moving averages, reference zones',svg(series),
            'Support/resistance here are prior 30 daily close extremes, excluding today. They are not OHLC swing points or guaranteed reversal levels.')
        for title,field,percent in [('Drawdown from observed peak','drawdown',True),
                                    ('30-day annualized realized volatility','annualized_volatility_30d',True),
                                    ('RSI 14 — Wilder smoothing','rsi14_wilder',False)]:
            body+=panel(coin+' — '+title,svg([(title,[(row['date'],row[field]) for row in data if row[field] is not None])],percent),
                'Close-based diagnostics. Volatility uses a 365-day crypto annualization; RSI can remain extreme during a trend.')
        for label,results in backtests[coin].items():
            body+=panel(coin+' — '+label+' holdout returns',svg([
                ('Actual',[(row['date'],row['actual_return']) for row in results]),
                ('Model',[(row['date'],row['model_return']) for row in results])],True),
                'Log returns, not prices. Errors are evaluated only on chronological held-out observations.')
            errors=[(row['date'],row['model_return']-row['actual_return']) for row in results]
            body+=panel(coin+' — prediction error',svg([('Predicted minus actual log return',errors)],True))
        annual=[row for row in (coin_yearends or []) if row['coin']==coin]
        if annual:
            body+=panel(coin+' — year-end price scenarios through 2030',svg([
                (label,[(row['date'],row[field]) for row in annual]) for label,field in [
                    ('P05 USD','price_p05_usd'),('Median USD','price_median_usd'),('P95 USD','price_p95_usd')]]),
                'Historical resampling scenarios, not reliable price targets. Lines between year-end points are visual guides, not daily estimates.')
        body+='</div>'
    body+=panel('Historical forecasting scores',table(['Coin','Feature set','Model','N','Return MAE','Return RMSE'],[
        [row['coin'],row['features'],row['model'],row['n'],f'{row["return_mae"]:.5f}',f'{row["return_rmse"]:.5f}'] for row in metrics]),
        'Compare each model with zero-return persistence and historical mean. No trading returns are inferred.')
    # Macro series each get a separate scale rather than misleading dual axes.
    body+=panel('Gold proxy — GLD adjusted ETF close',svg([('GLD adjusted USD',[(str(d),v) for d,v in gold.items()])]),
        'ETF proxy, not physical spot gold. Weekends and market hours differ from crypto.')
    body+=panel('US M2 money supply',svg([('M2SL billions USD',[(str(d),v) for d,v in m2.items() if common[0]<=d<=common[-1]])]),
        'Monthly, seasonally adjusted, latest revised observations. Not global M2 or proof of causation. See macro_correlations.csv for growth-rate comparisons.')
    for title,scenario in [('One-year historical scenarios',paths),('Long-term historical scenarios through 2030',long_paths)]:
        body+=panel(title,svg([(field,[(row['date'],row[field]) for row in scenario]) for field in ['p05','median','p95']]),
            'USD portfolio value. Marginal percentiles from joint block resampling, not calibrated prediction intervals. No future crisis, gold or money-supply path is known.')
    body+=panel(portfolio_label,table(['Coin','Weight','USD value at valuation','Units'],[
        [c,f'{v["weight"]:.2%}',f'{v["allocation_usd"]:,.2f}',f'{v["units"]:.6f}'] for c,v in sorted(holdings.items())]),
        'Positions are valued at the common historical input close, not guaranteed live executable prices. Weights are descriptive, not recommended allocations.')
    note='SYNTHETIC TEST PREVIEW — no real historical performance' if synthetic else 'Research output — inspect provenance and data quality before interpretation'
    doc='<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Crypto Research Charts</title><style>'+\
        '*{box-sizing:border-box}body{background:#0b1323;color:#e9f2ff;font:15px/1.65 system-ui;margin:0}main{max-width:1300px;margin:auto;padding:36px 24px}h1{font-size:36px}h2{font-size:21px;margin-top:0}p{color:#afc0dc}.panel{background:#132039;border:1px solid #293950;border-radius:14px;padding:24px;margin:22px 0}.notice{background:#332b19;color:#ffdc9a;padding:18px;border-radius:10px}svg{width:100%;height:auto}svg text{font:12px system-ui;fill:#aac0dd}svg text[fill]{fill:revert-layer}.scroll{overflow:auto}table{border-collapse:collapse;width:100%}th,td{padding:10px;border-bottom:1px solid #293950;text-align:left;white-space:nowrap}th{color:#aac0dd}.selector{display:block;position:sticky;top:0;background:#0b1323;padding:15px;z-index:2}select{font:inherit;padding:8px;background:#132039;color:white;margin-left:15px}a{color:#6da8ff}[hidden]{display:none!important}'+\
        '</style><main><p>gresium / crypto portfolio research</p><h1>Market Structure &amp; Portfolio Scenarios</h1><div class="notice">'+esc(note)+\
        '</div><p>Dates reflect input files. Technical indicators summarize past closes; future paths are conditional historical-resampling scenarios. Read TRADING_GLOSSARY.md for terminology.</p>'+body+\
        '</main><script>document.getElementById("coin").addEventListener("change",function(){document.querySelectorAll(".coin").forEach(s=>s.hidden=s.dataset.coin!==this.value)});</script></html>'
    (out/'report.html').write_text(doc,encoding='utf-8')
