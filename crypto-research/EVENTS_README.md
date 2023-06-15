# Why News, Crises, and Hacks Can Move Crypto

Prices reflect changing expectations, liquidity, positioning, and available buyers and sellers. An announcement can cause a move when it changes those expectations; its importance is not determined solely by whether the headline sounds positive or negative.

## Mechanisms

| Event type | Possible channel | Why direction is uncertain |
|---|---|---|
| Rate decisions and inflation surprises | Discount rates, dollar conditions, financing costs, risk appetite | Markets react to the surprise relative to expectations; guidance may dominate the headline |
| Crisis or bank/exchange failure | Demand for cash, counterparty fear, forced liquidations, withdrawals | Initial selling can be followed by recovery as liquidity or policy expectations change |
| Hacks and bridge exploits | Direct losses, token selling, frozen withdrawals, trust shock | Impact depends on assets affected, size, reimbursement, containment, and whether news was already known |
| ETF or regulatory decisions | Access to investment products, uncertainty, expected demand | Approval can be anticipated, followed by profit-taking or disappointing flows |
| Token unlocks and issuance | Changes to available supply and expected selling | Supply changes may be prepriced; recipients need not sell immediately |
| Protocol upgrades or outages | Reliability, utility, fee expectations, operational risk | Planned news may be discounted; execution and adoption matter |
| Rumours and corrections | Rapid expectation changes and crowded positioning | An unverified report can reverse when corrected |

Leverage can amplify both directions: falling collateral may trigger liquidation selling, while short covering can accelerate a rally. Thin liquidity means a relatively small order can move price sharply. These are mechanisms to investigate, not rules that predict every outcome.

## Two sourced historical examples

1. **2024-01-10: SEC approval of spot Bitcoin ETP listings.** The SEC statement confirms the approval. This is an event marker, not evidence that every coin rose that day. [Primary source](https://www.sec.gov/newsroom/speeches-statements/gensler-statement-spot-bitcoin-011023).
2. **2025-02-21: Bybit theft.** The FBI states the theft occurred “on or about” this date. Its attribution notice was published on 26 February, a different date. The event file uses the approximate incident date, not the later notice date. Exact first-public timestamps require further research. [Primary source](https://www.ic3.gov/PSA/2025/PSA250226).

These seeds demonstrate regulatory and hack categories. Crisis, rate-decision, inflation, and other examples can be added with primary-source links and carefully defined timestamps. No sentiment labels are automatically converted into buy/sell signals.

## Event measurement implemented here

For an event dated D, compare the close at D-1 with closes at D, D+1, and D+7. The code requires both exact dates; missing observations are skipped rather than replaced by a conveniently selected neighbouring date.

The result is a **raw event-window return**. It is not an abnormal return adjusted for market conditions and not an estimate of the event's causal effect. A post-event decline does not prove the event caused it. Daily closes cannot distinguish an announcement before the close from an announcement after it, and different providers use different timestamp conventions.

The event catalogue is deliberately retrospective. It is not supplied to the forecasting model, avoiding the false impression that tomorrow's hacks or unscheduled crises were known in advance. A prospective scheduled-event model would need historically available calendars, surprise measures, and release-time alignment.

## Better event research

- Record incident time, first-public report time, confirmation time, timezone, and source separately.
- Compare affected tokens with suitable controls over matching periods.
- Inspect pre-event moves, volume, broad market returns, and overlapping announcements.
- Define windows before inspecting outcomes; report all selected events rather than only dramatic examples.
- Account for multiple testing, selection bias, and dependence between events.
- Distinguish a hack's direct asset loss from an exchange's solvency or token-price movement.

## M2 and gold context

Money-supply growth may coincide with changing financial conditions, but US M2 is not money automatically flowing into crypto. Rates, bank deposits, credit, fiscal flows, demand, and global conditions can move differently. A lag picked because it fits a chart is not a proven forecasting relationship.

Gold can attract demand in some risk-off episodes, but can also be sold during a cash squeeze. Its relationship with crypto varies by horizon and regime. This project compares GLD adjusted ETF returns, not a claim that all physical gold and crypto react alike.

Use these comparisons to ask better questions about a move, not to promise an explanation for every dip or high.
