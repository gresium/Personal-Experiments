# Validation Status

Prepared on 5 November 2026 against the supplied existing repository code.

## Executed successfully

```text
python -m unittest -v
Ran 13 tests
OK

python -m py_compile research.py charts.py download_data.py test_research.py
Exit status: 0
```

Tests cover next-day target alignment, invariance of an origin prediction to future price changes, training-only standardization, delayed macro alignment, reproducible budget-balanced holdings, shared-return scenario sampling, missing-date handling, duplicate-date rejection, and end-to-end output generation in both price-only and exploratory-macro modes.

All test market values are synthetic fixtures. Temporary test outputs are removed after tests. They do not demonstrate predictive skill, investment returns, historical correlations, or real event effects.

Additional tests verify that reference support/resistance excludes today's close and that per-coin year-end scenario percentiles are ordered and reach the requested endpoint. The end-to-end tests now also generate the HTML chart report, technical CSVs, and long-term outputs. `preview_demo.py` produces a synthetic visual preview with clearly named fixture assets; it is not market evidence.

Custom-portfolio validation additionally covers mixed coin-quantity/USD inputs, budget and weight calculations, rejection of negative amounts and unsafe symbols, and an end-to-end custom portfolio run using a configuration-relative position file. The interactive setup script was syntax-checked; live provider coverage remains untested here.

## Historical-data attempt

A direct request to the genuine FRED M2SL CSV endpoint was attempted from this runtime. It failed with DNS resolution error (`getaddrinfo failed`). The runtime also lacked the downloader dependencies. Consequently, a real historical market-data download/backtest was **not completed** here. No historical metric tables or market charts were fabricated or bundled.

The downloader path was syntax-checked, but could not be integration-tested against live Yahoo/FRED responses. Run the documented commands on a network-enabled machine before publishing performance claims. Provider schema changes, symbol coverage, rate limits, and adjustment conventions require inspection of the downloaded data.

## Repository review findings addressed

- Original next-day model used the same latest row for fitting and prediction without shifting to a future target.
- Original rolling features could describe the target price itself during same-row fitting.
- Original scripts used inconsistent hardcoded holdings and did not evaluate held-out forecasting skill.
- The old annual script used Prophet without documented historical validation.
- An embedded CoinMarketCap credential was omitted from this package; rotate it if active.

## Remaining research limitations

The model choice and regularization are fixed rather than tuned through nested time-series validation. There is no claim of superior accuracy. Annual scenarios resample historical regimes and cannot model unforeseen crises. Event windows are descriptive and retrospective. Macro augmentation uses revised M2 with an assumed delay, not historical release vintages. Today's coin universe introduces survivorship bias.
