"""Download genuine daily closes and current-vintage US M2; never fabricate data."""
import argparse
import csv
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='config.json')
    parser.add_argument('--data', default='data')
    args = parser.parse_args()
    import yfinance as yf
    cfg = json.loads(Path(args.config).read_text())
    from research import validate_coins
    validate_coins(cfg['coins'])
    out = Path(args.data)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {'retrieved_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                'requested_start': cfg['start'], 'end_exclusive': cfg['end'],
                'files': [], 'errors': [], 'm2_vintage': 'latest revised, not point-in-time'}
    for coin in cfg['coins'] + ['GOLD']:
        ticker = 'GLD' if coin == 'GOLD' else cfg.get('coin_tickers',{}).get(coin,coin+'-USD')
        try:
            df = yf.download(ticker, start=cfg['start'], end=cfg['end'],
                             auto_adjust=True, progress=False, threads=False,
                             multi_level_index=False, timeout=30)
            close = df['Close'].dropna()
            if close.empty:
                raise ValueError('No daily observations returned')
            path = out / (coin + '.csv')
            with path.open('w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['date', 'close'])
                for date, value in close.items():
                    writer.writerow([date.date().isoformat(), float(value)])
            manifest['files'].append({'file': path.name, 'ticker': ticker,
                'source': 'Yahoo Finance through yfinance', 'adjusted': True,
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'rows': len(close)})
        except Exception as exc:
            manifest['errors'].append({'asset': coin, 'error': str(exc)})
    try:
        url = 'https://fred.stlouisfed.org/graph/fredgraph.csv?id=M2SL'
        request = urllib.request.Request(url, headers={'User-Agent': 'crypto-research/1.0'})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode('utf-8-sig')
        rows = list(csv.DictReader(io.StringIO(raw)))
        if not rows or 'M2SL' not in rows[0]:
            raise ValueError('Unexpected FRED response')
        path = out / 'M2.csv'
        with path.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['date', 'value'])
            for row in rows:
                value = row['M2SL']
                if value not in ('', '.'):
                    writer.writerow([row.get('observation_date', row.get('DATE')), value])
        manifest['files'].append({'file': 'M2.csv', 'source': url,
            'units': 'billions USD, monthly, seasonally adjusted',
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    except Exception as exc:
        manifest['errors'].append({'asset': 'M2', 'error': str(exc)})
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    if manifest['errors']:
        print(json.dumps(manifest['errors'], indent=2))
        raise SystemExit('Incomplete download. Resolve errors before running the full study.')
    print('Downloaded genuine observations. See data/manifest.json for provenance.')


if __name__ == '__main__':
    main()
