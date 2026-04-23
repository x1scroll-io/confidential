# x1scroll Confidential Transfers

**Programmable privacy for XNT. First on any SVM chain.**

Shield your balance — transfer without revealing amounts. Reveal voluntarily for compliance. Solana can't do this without a hard fork. X1 can do it now.

## How It Works
1. `shield()` — deposit XNT, get a commitment. Balance hidden on-chain.
2. `confidential_transfer()` — move balance via commitment swap. Sender/recipient/amount all hidden.
3. `unshield()` — withdraw XNT. Amount revealed on exit (unavoidable).
4. `voluntary_reveal()` — owner discloses balance to auditor. Regulator-compliant.

## Privacy Model
- **On-chain visible:** commitments only (hash of balance + salt)
- **Off-chain (owner holds):** view key = the salt that unlocks the commitment
- **Compliance path:** owner can voluntary_reveal() at any time
- **No anonymity set required** — works from day 1 with any number of users

## Program ID
`AgfGDh4SKaviYos96U2XhNyD3qR829muuG2qvF544t3v` — live on X1 mainnet

## Fees
- Shield: free
- Confidential transfer: 0.005 XNT → 50% treasury / 50% burned 🔥
- Voluntary reveal: 0.001 XNT → 50% treasury / 50% burned 🔥

Built by x1scroll.io | @ArnettX1
