# RISEx — Resting Order-Book Manipulation Inflates Mark Price and Enables Settled Collateral Withdrawal

**Validation status:** Live testnet verified; mainnet data flow confirmed read-only; production exploitability and bad-debt ceiling not tested.

**Suggested severity:** High (provisional)

**Test date:** 31 August 2026

## Summary

RISEx derives its mark price from order-book impact prices that an ordinary trader can materially influence with large, paired post-only limit orders. The attacker-controlled orders do not need to be fully filled. While the manipulated pair remains open, a second attacker-controlled account with a position receives an inflated withdrawable-collateral value and can settle an on-chain testnet-USDC token withdrawal from the Collateral Manager.

I verified the full state-change chain on RISEx testnet (chain ID `11155931`):

1. Account B opened a small `0.005 BTC` long.
2. Account A placed a paired post-only bid/ask worth approximately `$25,000` per side.
3. The contract-reported impact bid/ask became exactly `80249.8 / 80249.9`.
4. The mark price increased by `337.38821923138` USD (`43.0275 bps`) while the index moved by only `-0.99985752126` USD (`-0.1269 bps`).
5. B's withdrawable collateral increased by `1.6645441580262 USDC` immediately after placement and by `1.7272552217595428 USDC` before withdrawal.
6. B withdrew `1.000000 testnet-USDC` on-chain while both A orders still had an `OPEN` state.
7. The pair was cancelled and all A/B positions were flattened. Final verification showed no remaining A orders and no A/B market-1 positions.

This is a live testnet proof of the manipulation and settled testnet-USDC withdrawal primitive. I did not broadcast any mainnet transaction. Mainnet profitability and maximum bad-debt impact should be assessed by the team against live liquidity and risk limits.

## Suggested severity

**High (provisional)** — an ordinary authenticated trader can influence collateral accounting and settle a token withdrawal. The test intentionally capped extraction at 1 USDC and did not create bad debt. A Critical rating would require demonstrating that the same flow is profitable at current mainnet liquidity and can withdraw more than the attacker's legitimate equity before liquidation/risk controls intervene.

## Affected components

- Orders Manager / order-book impact-price calculation
- Oracle mark-price EMA synchronization
- Perps Manager withdrawable-collateral calculation
- Collateral Manager `withdraw(address,address,uint256)`
- Testnet REST order endpoints used by ordinary authenticated users

## Root cause

The mark-price path treats attacker-posted resting depth as an economically reliable price signal before it has executed. A trader can therefore bracket the impact-notional threshold with self-cancelable post-only orders and move the impact midpoint. The manipulated mark is then consumed by the withdrawable-collateral path without a sufficient liquidity-quality, persistence, or manipulation-resistance check.

## Preconditions

- Two ordinary attacker-controlled accounts.
- Account A has enough margin to rest the paired orders.
- Account B has a position whose unrealized PnL benefits from the chosen mark direction.
- The order pair remains live long enough for the mark update and withdrawal.

No administrator, oracle-signer, or privileged contract role was used.

## Reproduction environment

- API: `https://api.testnet.rise.trade`
- RPC: `https://testnet.riselabs.xyz`
- Chain ID: `11155931`
- Market: `1` (BTC)
- Account A: `0xD903bEB2fb62fB5bB9dA83391dB49768226fac46`
- Account B: `0x5941a349ED4A5116Fad165d3AAB13CcA3b6a07dD`
- Runner attachment: `rise_phase_b_testnet.py`

The runner hard-pins the chain ID, caps the withdrawal at 1 USDC, requires both impact orders to remain live, stores no secrets in evidence files, and performs cleanup.

## Step-by-step PoC

The two disposable accounts must already be funded with test collateral and have registered session signers. JWT and private-key files are local mode-0600 files and must not be attached to the report.

```bash
# 1. Refresh short-lived testnet JWTs.
python3 rise_phase_b_testnet.py approve-jwt

# 2. Open the small beneficiary fixture: 5,000 size steps = 0.005 BTC.
python3 rise_phase_b_testnet.py open-b-long --b-size-steps 5000

# 3. Place and contract-verify the approximately $25k-per-side impact pair.
python3 rise_phase_b_testnet.py start-a-impact

# 4. Monitor both A order IDs, permissionlessly sync the EMA, and stop once
#    B's withdrawable delta reaches 1 USDC.
python3 rise_phase_b_testnet.py monitor-impact \
  --duration 180 --interval 10 --withdraw-usdc 1

# 5. Settle exactly 1 USDC to B while both impact orders remain OPEN.
python3 rise_phase_b_testnet.py withdraw-b --withdraw-usdc 1

# 6. Cancel the pair, close any partial fills, and prove A/B are flat.
python3 rise_phase_b_testnet.py cleanup
python3 rise_phase_b_testnet.py snapshot
```

## Transaction evidence

### Beneficiary position

- B opens `0.005 BTC` long:
  - `0x988e85834808d460a787f7cb2ad21e89eaec243cb9893d81119c39061a068d57`

### Manipulative pair

- A buy, `0.311528 BTC @ 80249.8`, notional `25000.0596944 USDC`:
  - `0xe646908ed75e5ba59790108e763e0b3371457338a25d78eda412c1b03e25271b`
- A sell, `0.311528 BTC @ 80249.9`, notional `25000.0908472 USDC`:
  - `0xf6924d9b3d72e162d2b37542bb4760d2f29a313d4d8d1c65735b17a6b69d172b`
- Verified contract impact prices while both were open:
  - bid `80249.8`
  - ask `80249.9`

### Permissionless sync

- Index-block EMA sync:
  - `0x66a54e2bb11666e508f855076bfb58e580da563cd5b23c44436b809d69421642`
- Mark-price EMA sync:
  - `0x76658d0f15a667d1aec63515d60471f81439f45426b8ce473411d269ddb2628e`

### Settled withdrawal

- B withdraws `1,000,000` token units (`1 USDC`) at block `53120018`:
  - `0xc45a29b2bed07e66e3c5a3b8ad3cfcdbba02a4af36b4caf9e181e36d1dbbe8e5`
- Wallet token delta:
  - before: `0`
  - after: `1,000,000`
- Incremental withdrawable immediately before withdrawal:
  - `1.7272552217595428 USDC`
- Both A impact order IDs were still open after settlement.

### Cleanup

- A pair cancelled:
  - `0x56437d6fc998422c7482901f2648046cf979de17a46f366fb6e42e0c0bf960d5`
- Final cleanup transaction for A's net partial fill:
  - `0x99096b8ae1c741a5eec8bcaf7624e96f981a5656c600962b6090617e77dc2576`
- Final state:
  - A open orders: `0`
  - A market-1 position: `0`
  - B market-1 position: `0`

## Numerical causality

| Metric | Baseline | After pair placement | Change |
|---|---:|---:|---:|
| Index price | 78781.62369399001 | 78780.62383646875 | -0.99985752126 |
| Mark price | 78412.1400483262 | 78749.52826755758 | +337.38821923138 |
| B withdrawable USDC | 705.8831962205756 | 707.5477403786018 | +1.6645441580262 |

The index was essentially unchanged while the mark and B's withdrawable collateral moved in the direction implied by A's pair.

## Fill and cost disclosure

The pair was not fully fill-free. Before cancellation:

- A buy filled `0.013414 BTC @ 80249.8`.
- A sell filled `0.017142 BTC @ 80249.9`.
- The net `0.003728 BTC` short was closed at `80250` during cleanup.

The gross round trip was approximately `+0.0009686 USDC`; using the reported `200` fee units as `0.02%`, estimated trading fees were approximately `0.5502573 USDC`, for approximately `0.5493 USDC` net manipulation-trade cost. The proof withdrew 1 USDC. This excludes the deliberately conservative cost of opening and later closing B's test fixture in the sparse testnet book.

This disclosure matters: the result proves the accounting and withdrawal primitive, but a mainnet severity decision should use real liquidity, fill probability, fees, position limits, and liquidation behavior.

## Security impact

An attacker can use a beneficiary position to convert a temporary, attacker-created order-book signal into withdrawable collateral. At sufficient scale this can:

- allow withdrawal of collateral backed only by manipulated unrealized PnL;
- leave the beneficiary account undercollateralized after the orders are cancelled and the mark normalizes;
- transfer resulting bad debt to the protocol, insurance fund, or counterparties;
- manipulate liquidation eligibility and liquidation prices for other accounts using the same mark path.

The submitted proof demonstrates settled token movement but intentionally does not create bad debt or test third-party positions.

## Mainnet applicability and limitation

Read-only mainnet-state calibration previously confirmed that the same mark-price and withdrawable-collateral dependency exists, but current mainnet books require materially more displayed depth than this testnet proof. No mainnet write was broadcast. Please reproduce internally with production state or a mainnet fork before assigning a drain ceiling.

Accordingly, this report does **not** claim a verified live-mainnet drain, infinite profit, or a Critical severity ceiling.

## Recommended remediation

1. Do not calculate margin, liquidation, or withdrawable collateral from raw resting-order impact prices.
2. Anchor the mark to manipulation-resistant oracle/TWAP data and cap order-book deviation against the external index.
3. Apply minimum persistence and executed-volume requirements before order-book changes affect collateral accounting.
4. Exclude or heavily discount newly placed, self-cancelable, concentrated, or same-entity liquidity from the impact calculation.
5. Apply withdrawal haircuts or delay withdrawals when the mark/index basis changes abruptly or liquidity quality is low.
6. Add circuit breakers for excessive mark/index divergence and alert on paired symmetric depth that appears immediately before withdrawal.
7. Test the invariant: cancelling all unfilled orders must not turn a previously allowed withdrawal into protocol bad debt.

## Attached evidence

- `rise_phase_b_testnet.py`
- `rise-phase-b-evidence/impact-phase-state.json`
- `rise-phase-b-evidence/impact-timeline.json`
- `rise-phase-b-evidence/impact-timeline.csv`
- `rise-phase-b-evidence/b-incremental-withdrawal.json`
- `rise-phase-b-evidence/post-proof-cancel-a.json`
- `rise-phase-b-evidence/phase-b-cleanup.json`
- `rise-phase-b-evidence/phase-b-readonly-snapshot.json`
- `rise-oracle-mainnet-calibration-20570116.md` (read-only mainnet-state calibration)

