# RISEx Oracle Candidate — Mainnet-State Calibration

## Verdict

**CONFIRMED on a local fork of current mainnet state; NOT live-exploit verified.**

The financial dependency reproduced at both the original pinned block and block `20570116`. Mainnet was used only for RPC reads, API market data, and fork state. No transaction was broadcast to mainnet.

## Latest-state fork evidence

- Chain ID: `4153`
- Fork block: `20570116`
- Block timestamp: `2026-08-31T11:31:16Z`
- Target market: `12` (`LIT/USDC`)
- EMA elapsed time: `480 seconds`
- Fixture: public account state already holding a long market-12 position

| Scenario | Mark price | Mark delta | Withdrawable USDC | Withdrawable delta |
|---|---:|---:|---:|---:|
| Neutral | 3.704672014054140656 | 0 bps | 168,720.640255064474885673 | 0 |
| High injected impact | 3.716511161971809589 | +31.957344 bps | 169,258.542469385428721381 | +537.902214320953835708 |
| Low injected impact | 3.692832866136471723 | -31.957344 bps | 168,182.738040743521049965 | -537.902214320953835708 |

High-to-low withdrawable range: `1,075.804428641907671416 USDC`.

Evidence checksums:

```text
70f0d519e8ad5da4b7c8f99beb91763856b97f618db77bfac9abe86d1e696e3c  results.csv
8dab0398c6b810e83d16cd47fd44c97d1b80f90925140217368975c939dc35d0  high-sync-receipt.json
02a1d73060259c057c28a4a8cc41251114453732ea76a41b032998f584b9f81d  low-sync-receipt.json
5d32c34c932f9a7d80c70f84c1a022cf23897b3f89e1535b2eabbdda3676f718  neutral-sync-receipt.json
```

## Mainnet read-only calibration

The public market/orderbook API was sampled while the chain advanced from approximately block `20570116` to `20570936`; therefore this is a time-bounded liquidity snapshot, not an atomic guarantee.

- Markets configured: `28`
- Active markets: `26`
- `getImpactNotionalBaseUsdc(uint16)` returned `50` for all market IDs 1–28.
- Every sampled active book had both sides and sufficient returned depth to cover the ±50 bps calculation.

Cheapest estimated displayed depth that would have to be crossed/displaced to move one side to ±50 bps from index:

| Market | Mark/index deviation | Spread | Upward displayed notional | Downward displayed notional |
|---|---:|---:|---:|---:|
| 15 AERO/USDC | -10.718 bps | 3.348 bps | $69,640.78 | $58,036.11 |
| 11 VVV/USDC | -2.035 bps | 4.520 bps | $64,256.14 | $61,873.75 |
| 8 ZEC/USDC | +4.406 bps | 5.015 bps | $65,050.51 | $79,574.13 |
| 16 AAVE/USDC | +0.325 bps | 16.787 bps | $67,502.80 | $67,284.35 |
| 7 TAO/USDC | +1.371 bps | 4.348 bps | $69,985.87 | $69,786.40 |
| 12 LIT/USDC | -8.370 bps | 6.505 bps | $108,163.70 | $78,993.82 |

Market-12 API snapshot:

```text
index_price       3.6893880943385
mark_price        3.6863
best-spread       6.505143776 bps
bid levels        50
ask levels        22
up-to-50bps depth $108,163.69768
down-to-50bps     $78,993.82439
```

The injected fork scenario used impact prices at 90%/100%/110% of index. The displayed-depth figures above cover only ±0.5%, so they are conservative capital/depth lower bounds, not a claim that displayed notional equals irreversible attacker loss. Actual economics must include fills, fees, spread, slippage, funding, hedging, inventory PnL, and market-maker refill during the EMA window.

## Mainnet-adjusted decision

Current state does not support a cheap live manipulation claim. The candidate remains suitable for a controlled two-account sandbox test, using market 12 for consequence reproducibility or an isolated sandbox market with equivalent configuration.

Promote to a reportable lost-funds issue only if all are proven:

1. Account A's non-crossing orders remain open and materially shift the impact/mark inputs.
2. No third-party liquidity is crossed or consumed.
3. Account B independently gains withdrawable collateral.
4. B settles a capped withdrawal while A's orders remain open.
5. Incremental withdrawal exceeds all realized A+B costs.
6. Canceling A's orders reverses the effect, followed by complete cleanup.

Until then, the accurate label is: **fork-confirmed economic consequence, attacker reachability and profitability unconfirmed**.
