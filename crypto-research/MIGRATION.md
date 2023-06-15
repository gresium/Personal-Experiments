# Applying This Upgrade to the Existing Repository

Original folder: `Crypto Portofolio Forecasting/` in `gresium/Blockchain-Cryptocurrencies`.

1. Keep a copy or git commit of the original scripts and generated outputs.
2. Place this package's files in a new `research-v2/` subfolder initially. Run it there so old and new outputs are not confused.
3. Install dependencies, download genuine inputs, then run both price-only and exploratory macro studies.
4. Compare held-out errors with persistence before describing the new model as more accurate.
5. Once reviewed, decide whether to replace the old entry points or retain them as an archived experiment.

`research.py` supersedes the next-day forecasting and aggregation workflow. `download_data.py` replaces the original data fetch path. The annual output is now a scenario distribution rather than a Prophet projection. No old metrics or plots should be relabelled as results from the new model.

The old `portofolio.py` contains a hardcoded CoinMarketCap credential. Revoke/rotate it if active and remove it from maintained code; removal in a later commit does not erase it from repository history. This package does not reproduce it or depend on it.

No remote repository changes were made while preparing this package.
