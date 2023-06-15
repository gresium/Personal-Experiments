"""Interactive coin/position setup. Personal inputs stay in local ignored JSON files."""
import argparse
import json
import math
from pathlib import Path
from research import validate_coins


def amount(prompt):
    while True:
        try:
            value=float(input(prompt).strip())
            if not math.isfinite(value) or value<=0:
                raise ValueError()
            return value
        except ValueError:
            print('Enter a positive number using a decimal point, for example 0.125 or 250.')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--base-config',default='config.json')
    parser.add_argument('--name',default='my')
    args=parser.parse_args()
    if not args.name.isalnum():
        raise SystemExit('Use a simple letters/numbers-only profile name.')
    config_path=Path(args.name+'-config.json')
    portfolio_path=Path(args.name+'-portfolio.json')
    if config_path.exists() or portfolio_path.exists():
        answer=input('This profile exists. Replace its local configuration? [y/N] ').strip().lower()
        if answer!='y':
            raise SystemExit('No files changed.')
    cfg=json.loads(Path(args.base_config).read_text(encoding='utf-8'))
    positions={}; tickers={}
    print('Build a portfolio. Use coin symbols, not contract addresses. Blank coin finishes.')
    print('Market prices are fetched later; unsupported symbols will produce a visible download error.')
    while True:
        coin=input('Coin symbol (BTC, ETH, BNB, etc.): ').strip().upper()
        if not coin:
            if positions:
                break
            print('Add at least one coin.'); continue
        try:
            validate_coins([coin])
        except ValueError as exc:
            print(exc);continue
        if coin in positions:
            print('Already added. Finish and edit the profile to change an entry.');continue
        ticker=input(f'Yahoo Finance ticker [{coin}-USD]: ').strip() or coin+'-USD'
        while True:
            mode=input('Enter (1) coin quantity or (2) USD amount to allocate: ').strip()
            if mode in ('1','2'):
                break
            print('Choose 1 or 2.')
        key='units' if mode=='1' else 'value_usd'
        value=amount('Quantity: ' if key=='units' else 'USD amount: ')
        positions[coin]={key:value}
        tickers[coin]=ticker
    cfg['coins']=list(positions)
    cfg['coin_tickers']=tickers
    cfg['portfolio_file']=portfolio_path.name
    portfolio_path.write_text(json.dumps({'positions':positions},indent=2),encoding='utf-8')
    config_path.write_text(json.dumps(cfg,indent=2),encoding='utf-8')
    print('\nCreated',config_path,'and',portfolio_path)
    print(f'Next: python download_data.py --config {config_path} --data data/{args.name}')
    print(f'Then: python research.py --config {config_path} --data data/{args.name} --output results/{args.name}')
    print('Keep profile and result files private if they contain real holdings.')


if __name__=='__main__':
    main()
