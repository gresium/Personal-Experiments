# Crypto Portfolio Research: Forecasts, Macro Context, and Events

**Author:** [gresium](https://github.com/gresium)

An upgraded research pipeline for [Crypto Portofolio Forecasting](https://github.com/gresium/Blockchain-Cryptocurrencies/tree/main/Crypto%20Portofolio%20Forecasting). It separates next-day prediction, historical evaluation, macro comparisons, and long-term scenarios instead of presenting one smooth curve as a reliable future outcome.

## What's included

- Ten configurable coins: BTC, ETH, BNB, SOL, XRP, ADA, AVAX, LINK, LTC, XLM. DOGE and DOT were removed; BNB remains included. These are a research selection, not a live popularity ranking.
- Genuine daily historical closes downloaded through yfinance, cached with provenance and checksums.
- US M2 money supply from FRED and adjusted GLD prices as a gold-market proxy.
- Correct next-calendar-day log-return target, expanding-window backtests, and baseline comparisons.
- Reproducible randomized example allocations and quantities, with no personal holdings embedded.
- One-year joint historical block-bootstrap portfolio scenarios.
- Event-window measurements and a separate [events README](EVENTS_README.md).
- CSV outputs and dependency-free SVG charts.
- A self-contained `report.html` with a coin selector, normalized price comparisons, technical charts, drawdowns, volatility, correlations, prediction errors, and long-term scenario charts.
- Per-coin year-end price scenario ranges and portfolio scenarios through **31 December 2030**.
- A [trading glossary](TRADING_GLOSSARY.md) covering trends, support/resistance, breakouts, RSI, moving averages, and execution vocabulary.

## Changes from the original code

| Original behavior | Upgrade |
|---|---|
| RandomForest trained on today's price and predicts the same last feature row | Features at close t predict log(P[t+1]/P[t]); labels are aligned explicitly |
| Rolling features include the price being predicted in-sample | Today's close is permitted only for forecasting the following close |
| No chronological holdout | Expanding-window evaluation with periodic refits |
| No baseline comparison | Compare ridge with zero-return/persistence and expanding historical mean |
| Different hardcoded holdings in different scripts | One seeded example-portfolio generator |
| Missing assets can become zero in portfolio sums | Missing configured coin files fail visibly |
| Prophet curve extrapolated a year without evaluation | One-year scenarios are explicitly separate from tested next-day models |
| Hardcoded external API credential | No embedded credentials or CoinMarketCap dependency |
| README dependency/run instructions do not match scripts | One documented download and research workflow |

The simpler standardized ridge model is intentional: evaluation comes before model complexity. It is not assumed to beat persistence.

## Run

Python 3.11+ recommended. Run from this folder.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS instead: source .venv/bin/activate
python -m pip install -r requirements.txt
python download_data.py
python research.py
python -m unittest -v
```

Open `results/report.html` in a browser after a successful run. It embeds its charts, needs no server, and makes no external requests. The dropdown switches coin-specific panels. The HTML can be generated from real downloaded data; any synthetic preview must be explicitly labelled with `--synthetic-test-data`.

For a no-network visual demonstration, open the bundled `preview.html`, or regenerate it with `python preview_demo.py`. Every price and macro input in that preview is synthetic and the assets are named FIXTURE_A/B/C. Do not publish its charts as historical market results.

The analysis engine and tests use only Python's standard library. pandas and yfinance are needed for the downloader. Version ranges are compatibility constraints, not a fully locked environment; record installed versions for published runs.

`config.json` contains the date range, coin list, budget, seeds, and evaluation settings. The default download ends **before 2026-11-05**, avoiding the unfinished day at project creation. Change the end date deliberately for later studies. A forecast after an old data endpoint is a historical-origin forecast, not a live quote.

For exploratory macro-augmented models:

```bash
python research.py --exploratory-macro --output results/macro
```

The downloader refuses to claim complete success if an asset fails. Do not silently omit a coin to improve results. Supply a new output directory for each study to avoid mixing runs.

## Data contracts and alternatives

Each coin file `data/BTC.csv`, etc., and `data/GOLD.csv`:

```csv
date,close
```

`data/M2.csv`:

```csv
date,value
```

Use ISO dates and finite positive values. Dates must be unique. The engine sorts dates and rejects duplicates. No coin prices are forward-filled across missing days. At least 31 consecutive daily closes are needed for each feature row and enough further history for train/test evaluation. The default minimum training size is 365 labelled rows.

GOLD is **GLD adjusted ETF close**, not physical gold spot price. Its returns reflect a traded fund, expenses, market hours, and adjustment conventions. Coin closes and US ETF closes are not simultaneous. Gold features therefore use at least a one-calendar-day delay, with a five-day staleness cap. Weekends and holidays remain visible in the alignment logic.

The built-in M2 source is **US M2SL**, monthly, seasonally adjusted, billions of USD. It is not global M2 and is not a daily money-printing series. No global aggregate is fabricated from unrelated currencies.

Downloaded FRED values are latest revised observations. The default price-only backtest never uses M2 features. Macro correlations are descriptive. The opt-in macro model imposes a **60-day assumed observation delay**, not an actual release calendar. This reduces one timing problem but does not remove revisions or guarantee historical availability. Label its results exploratory; a real-time macro test requires ALFRED vintages and actual release timestamps.

## Historical evaluation

For each coin, compute momentum, volatility, and moving-average deviation using information through origin close t. Predict the next day's log return. All training labels must end on or before that origin. Scaling is fitted only on the training subset. Ridge regularization is fixed in configuration rather than selected on the holdout.

The final 365 eligible observations are tested when available, with at least 365 training rows. Models refit every 30 test observations; between refits they remain fixed. The historical-mean baseline is updated with available labels. Dates are reported for each coin and can differ across assets. Opt-in macro and price-only comparisons use matched eligible dates.

Report MAE/RMSE of log returns, price MAE, direction accuracy, sample size, and actual dates. A zero-return prediction is treated as non-positive for direction scoring; it is not a useful directional classifier. Cross-coin price MAEs have different scales. Read return metrics first.

These are forecasting errors, **not trading profits**. There is no execution strategy, no fee/slippage modelling, no rebalancing backtest, and no claim of achievable returns from trading at the observed close. Fixed present-day coin selection introduces survivorship bias. A stronger study would include delisted/failed assets and a historically selected universe.

## Randomized example portfolio

### Use your own coins and holdings

Run the interactive setup:

```bash
python setup_portfolio.py
```

For each asset, enter its symbol and either a **coin quantity** or a **USD allocation**. Mix both input types across different coins if desired. A blank coin entry finishes setup. The wizard writes `my-config.json` and `my-portfolio.json`, then prints the exact download and analysis commands:

```bash
python download_data.py --config my-config.json --data data/my
python research.py --config my-config.json --data data/my --output results/my
```

Open `results/my/report.html`. Coin selections, charts, forecasts, scenarios and portfolio totals now use your positions. They do not depend on the ten default coins. A separate profile can be created with `python setup_portfolio.py --name demo2`.

New coins must have a valid supported Yahoo Finance price ticker and enough contiguous history. The wizard defaults to SYMBOL-USD but accepts a custom provider ticker. It cannot retrieve every token, contract address, exchange-only listing, or recently launched asset. A failed download or insufficient history is an error, never a silently omitted position. Gold and M2 remain benchmark inputs, not portfolio positions.

### Manual JSON example

```json
{
  "positions": {
    "BTC": {"units": 0.125},
    "ETH": {"value_usd": 750},
    "BNB": {"units": 1.8}
  }
}
```

The profile configuration must list exactly those symbols in `coins` and point `portfolio_file` to this JSON. Relative portfolio paths resolve from the configuration file's directory. Alternatively pass `--portfolio my-portfolio.json` to the research command. `coin_tickers` can map display symbols to provider tickers.

Coin quantities remain fixed. USD allocations are converted to quantities at the common **last input close**; they are not historical purchases or guaranteed live execution prices. Every amount must be finite and positive; zero, negative, duplicate-symbol and mismatched-position inputs are rejected. No cash, short positions, deposits, trading fees, or tax accounting are modelled.

Personal profiles and results are ignored by the included gitignore. Do not commit reports containing real holdings unless you intend to publish them. Remove `portfolio_file` from a copied configuration to return to the seeded random demo.

### Keep the random demo

The generator draws unequal positive allocation scores using a seeded RNG, normalizes them to a USD 10,000 example budget, and derives coin quantities from the common valuation close. Changing `portfolio_seed` changes holdings; changing `portfolio_budget_usd` changes the size. Historical prices are never randomized. The quantities are not the author's actual holdings and are not recommended allocations.

## One-year scenarios

Joint 14-day blocks of historical returns are sampled across all configured coins, preserving observed same-day co-movement and some within-block dependence. Units are held fixed. The output reports marginal 5th, 50th, and 95th percentiles over 365 simulated days.

This is a historical regime-resampling scenario, **not a calibrated prediction interval** or a model of future M2, gold, news, hacks, liquidity, or coin survival. Percentile lines are not necessarily individual realizable paths. Shared sampling history begins only when all selected coins have overlapping contiguous data. Historical drift and extreme returns may dominate outcomes.

## Outputs

| File | Meaning |
|---|---|
| `data/manifest.json` | Sources, retrieval time, checksums, download failures |
| `backtest_metrics.csv` | Historical errors for model and baselines |
| `<COIN>_<FEATURES>_backtest.csv` | Predictions, actual outcomes, and origins |
| `<COIN>_<FEATURES>.svg` | Actual vs predicted return chart |
| `next_day_forecasts.csv` | Price-only forecasts from the last common close |
| `example_holdings.csv` | Seeded example weights, USD amounts, and units |
| `portfolio_holdings.csv` | Actual selected input positions and their common-close valuations; generated for both modes |
| `portfolio_next_day.json` | Aggregated next-day example valuation |
| `portfolio_1year_scenarios.csv` | Historical resampling percentiles |
| `portfolio_scenarios.svg` | Scenario chart |
| `macro_correlations.csv` | Monthly GLD-return and M2-growth correlations |
| `event_windows.csv` | Raw returns around sourced event dates |
| `run_manifest.json` | Configuration and study caveats |
| `report.html` | Browser chart report with coin selector |
| `<COIN>_technicals.csv` | SMA 50/200, RSI 14, prior-close range, volatility, drawdown, descriptive labels |
| `portfolio_scenarios_2030.csv` | Daily portfolio scenario percentiles to configured long-term end |
| `portfolio_scenarios_2030.svg` | Long-term portfolio chart |
| `coin_price_scenarios_yearends.csv` | Year-end per-coin P05/median/P95 price scenarios |

Monthly correlations use available month-end observations, including a partial final month if the chosen end truncates a month. For publication use an end date after a completed month and inspect coverage. Lags of 1/2/3/6 months compare earlier M2 growth with later crypto returns; trying multiple lags is exploratory and invites data mining. Correlations of changes are used instead of two trending price levels, but even these are unstable across regimes.

## Technical charts and 2030 interpretation

Support/resistance lines use the previous 30 daily **closes**, excluding the current close. They are reproducible reference ranges rather than volume-confirmed order zones. SMA alignment and RSI describe historical conditions; they are not independently tested trading signals. No volume, candlestick OHLC, order-book, funding-rate, or liquidation data are collected in this version.

Year-end coin ranges and daily portfolio ranges through 2030 use the same joint return-block resampling as the one-year scenarios. They do not forecast future M2/gold paths, fundamentals, issuance changes, hacks, or asset failures. Historical drift can produce extreme compounding over multiple years. Do not label the median a guaranteed target or P05/P95 calibrated probabilities. A scenario from the end of an old input dataset remains a historical-origin scenario.

## Status and validation

See [VALIDATION.md](VALIDATION.md) for actual execution status. Offline synthetic fixtures test correctness only; they must never be reported as market backtest performance. Download/network failures do not trigger fake market data or invented metrics.

## Sources

- [yfinance source and usage](https://github.com/ranaroussi/yfinance) — a third-party interface, not an official Yahoo-supported API; respect provider terms and data permissions.
- [FRED M2SL](https://fred.stlouisfed.org/series/M2SL).
- [ALFRED M2 vintages](https://alfred.stlouisfed.org/series?seid=M2SL).
- [Events and sources](EVENTS_README.md).

Educational research software. Forecasts and scenarios do not establish that an asset will rise, that M2 causes a rally, or that a portfolio is safe.
