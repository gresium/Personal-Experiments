# Reading Crypto Charts: Trading Terms and Indicators

This guide explains the vocabulary used in the report. A label summarizes an observation or hypothesis; it does not establish an actionable trading edge.

## Trend and price structure

| Term | Meaning | How to interpret it carefully |
|---|---|---|
| Bullish / bearish | Expecting or describing upward / downward price pressure | A view, not a probability estimate |
| Uptrend | A sequence commonly described as higher highs and higher lows | Depends on timeframe and the definition of a swing |
| Downtrend | Lower highs and lower lows | A short downtrend can occur within a longer uptrend |
| Sideways / consolidation | Price oscillates within a range | A range can eventually resolve in either direction |
| Support | A zone where demand previously slowed declines | Can fail; a historical level is not a guaranteed floor |
| Resistance | A zone where supply previously slowed advances | Can be exceeded or briefly swept |
| Breakout | Price moves beyond a defined range or level | The level, timeframe, and confirmation rule must be specified |
| Breakdown | Price moves below a defined range or support | A temporary move can reverse |
| Fakeout / false breakout | A move beyond a level followed by a return inside | Often obvious only after the reversal |
| Retest | Price revisits a previously broken level | It does not have to occur or hold |
| Pullback / retracement | A counter-move within a broader trend | Distinguishing it from a reversal requires a defined method |
| Reversal | A change in the prevailing trend | One candle alone is weak evidence |
| Higher high / lower low | A high above an earlier high / a low below an earlier low | Requires a consistent swing-point rule |

### What this project actually calculates

The report draws the **lowest and highest of the prior 30 daily closes**, excluding the current close. These provide reproducible close-based reference zones. They are not intraday extremes, institutional order levels, or a full market-structure algorithm.

If the current close exceeds the previous 30-close high, the code labels it `above_prior_range`. Below the previous low becomes `below_prior_range`. Otherwise it is `within_range`. These labels are descriptive and are not validated breakout strategies.

## Indicators included in the report

| Indicator | Calculation | Limitation |
|---|---|---|
| SMA 50 | Mean of the latest 50 consecutive daily closes | Lags price; no guarantee of support |
| SMA 200 | Mean of the latest 200 consecutive daily closes | Long warm-up and slower response |
| Bullish alignment | Close > SMA 50 > SMA 200 | A heuristic, not a recommendation |
| Bearish alignment | Close < SMA 50 < SMA 200 | Can persist after a move has already happened |
| Mixed alignment | Neither ordering holds | Does not mean the market must be range-bound |
| RSI 14 | Wilder-smoothed average gains/losses over 14 daily changes | High or low RSI does not guarantee reversal |
| Realized volatility | Standard deviation of 30 daily log returns × sqrt(365) | Describes past movement; annualization assumes a scaling convention |
| Drawdown | Close / running observed peak − 1 | Starts at the first available observation, not necessarily the asset's lifetime peak |

RSI above 70 is often called **overbought** and below 30 **oversold**. These are conventions, not automatic sell/buy instructions. Strong trends can keep RSI elevated or depressed. A flat series is assigned RSI 50; zero losses with positive gains yields RSI 100.

A **golden cross** usually refers to a shorter moving average crossing above a longer one, often 50 above 200. A **death cross** is the opposite. The report displays moving averages and current alignment but does not separately detect or backtest these crossing signals.

## Returns, risk, and execution vocabulary

| Term | Meaning |
|---|---|
| Dip | An informal description of a price decline, without a universal threshold |
| Rally | A price advance, potentially within either a bull or bear market |
| Correction | A decline from a recent peak; thresholds vary by market/context |
| ATH / ATL | All-time high / low; requires sufficiently complete historical data |
| Volatility | Magnitude of price variation, not its direction |
| Liquidity | Ability to trade a quantity without materially moving the price |
| Volume | Quantity or value traded over a period; depends on venue and measurement |
| Spread | Difference between quoted bid and ask |
| Slippage | Difference between expected and obtained execution price |
| Long / short | Exposure that benefits from rising / falling prices |
| Leverage | Exposure greater than the capital posted |
| Liquidation | Forced position closure after margin requirements are breached |
| Stop-loss / take-profit | Planned exit conditions; fills at the exact level are not guaranteed |
| Risk/reward | Potential loss versus potential gain under a defined scenario |

The current project uses closes only: **no candlestick OHLC charts, volume confirmation, order books, liquidation maps, funding rates, or ATR are calculated**. A line chart cannot honestly display those missing inputs. They are potential extensions requiring additional data and testing.

## Long-term forecasts through 2030

The report includes daily example-portfolio scenario percentiles through the configured end date and year-end per-coin price percentiles. These are conditional on resampling the historical returns available at the valuation date. They are not price targets supported by future fundamentals.

- P05 / median / P95 are marginal scenario percentiles, not guaranteed lower/upper bounds.
- Paths can exceed the displayed range; 5%/95% are not calibrated real-world probabilities.
- Annual percentiles are not paths that one simulated portfolio necessarily follows.
- The model cannot foresee an exchange collapse, future hack, regulatory decision, new token supply regime, or asset failure.
- Historical drift, sample selection, and the chosen block size can dominate a multi-year result.

The further away 2030 is from the last input close, the stronger these limitations become. Use the output for stress discussion and method comparison, not certainty about a future price.
