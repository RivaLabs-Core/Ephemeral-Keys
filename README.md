# Ephemeral Keys

Protocol specification for quantum-safe Ethereum smart wallets built on single-use signing keys.

The signer rotates after every transaction. The smart account address does not. This eliminates the long-term public key exposure that Shor's algorithm exploits, without requiring any change to the Ethereum protocol.

This repo contains the spec, the security analyses, and the supporting annexes. Reference implementations live in separate repositories.

## Background

Ethereum accounts are secured by ECDSA over secp256k1. The private key never appears onchain, but the public key is exposed every time a transaction is signed. A sufficiently capable quantum computer running Shor's algorithm can recover the private key from the public key in polynomial time.

The protocol introduces two signing modes, both built on ERC-4337 account abstraction, both compatible with ERC-7579 modular accounts:

**ECDSA mode.** Each ECDSA key is used exactly once. After every transaction, the contract rotates to a fresh signer atomically inside `validateUserOp`. By the time a quantum adversary could recover the private key, the key is already retired. A residual mempool window remains and is mitigated by private mempools.

**WOTS+C mode.** Replaces ECDSA with WOTS+C, a hash-based one-time signature scheme. Security reduces to preimage resistance, not discrete log hardness. Observing a signature in the mempool reveals nothing actionable to a quantum adversary. Signature size is 292 bytes at NIST Level 1.

Both modes preserve a single stable account address. Both deploy as either a standalone ERC-4337 smart account or an ERC-7579 validator module installable on existing modular accounts.

## Repository map

The documents are layered. Start with the spec, then read the analyses for the parts you want to evaluate in depth.

### Protocol specification

**[`protocol-spec.md`](./protocol-spec.md)** is the entry point. Defines the threat model, account architecture, both signing modes, validation flow, key rotation, signature parameters, ERC-4337/7579/7702 conformance, and EIP-1271 limitations. This is the authoritative description of the protocol.

**[`protocol-spec-annex-a.md`](./protocol-spec-annex-a.md)** covers EIP-1271 compatibility. Explains why off-chain signature verification (Permit2, SIWE, Seaport, WalletConnect) is structurally hard with rotating signers and proposes a dedicated permit signer with an isolated key stream and its own rotation policy.

**[`protocol-spec-annex-b.md`](./protocol-spec-annex-b.md)** covers multi-wallet support under WOTS+C. Two wallets sharing the same seed and derivation path generate identical key sequences, which is catastrophic for a one-time scheme. The annex describes a wallet-bound salt mechanism that gives each wallet its own non-overlapping key stream while keeping the mnemonic as a complete backup.

### Security analyses

**[`1-abstract-protocol-analysis.md`](./1-abstract-protocol-analysis.md)** analyses the rotation mechanism independent of the signing primitive. Covers rotation atomicity, next-key commitment authentication, key consumption semantics, state synchronisation, the single-device constraint, mempool exposure, recovery path requirements, onchain state growth, composability, and reorg behaviour. Each finding is severity-tagged. Read this if you want to understand the protocol-level design choices and their tradeoffs.

**[`2a-ecdsa-only-analysis.md`](./2a-ecdsa-only-analysis.md)** is the ECDSA-mode-specific analysis. Quantifies the security lifetime as `T_Shor(secp256k1) >> Δ_max` (block-time gap), discusses recovery key longevity, harvest-now-decrypt-later resistance, mempool exposure, and the simpler composability profile that comes from ECDSA tolerating reuse.

**[`2b-pq-only-analysis.md`](./2b-pq-only-analysis.md)** is the WOTS+C-mode-specific analysis. Covers post-quantum unforgeability, the consequences of accidental key reuse (with concrete forgery probabilities), failure scenarios that risk reuse, key derivation, recovery options (WOTS+C pool vs SPHINCS+ vs FORS), the EIP-1271 incompatibility, and hash function selection.

**[`wots-param-security-analysis.md`](./wots-param-security-analysis.md)** is a parameter table for WOTS+C. Classical and quantum security across `w ∈ {4, 8, 16, 32, 64, 128, 256}` for the chosen `l`. The takeaway: all rows give roughly equivalent security at NIST level 1, so parameter choice is a gas-vs-signature-size engineering decision rather than a security one.

### Key derivation

**[`derivation-path-analysis.md`](./derivation-path-analysis.md)** specifies how a single BIP-39 mnemonic produces all four key kinds the wallet needs: WOTS+C ephemeral signers, ECDSA ephemeral signers, the EIP-1271 permit signer from Annex A, and a stateless post-quantum recovery signer. Defines the recovery seed vs wallet-bound seed split, the `wallet_id` mechanism, the four BIP-44 leaf paths, and the WOTS+C chain-seed expansion. Concludes that the entire derivation reduces to hash-function security with no discrete-log assumption anywhere.

## Suggested reading orders

**If you want a fast technical summary:** read `protocol-spec.md` only. 

**If you are evaluating the protocol design:** `protocol-spec.md`, then `1-abstract-protocol-analysis.md`. The numbered findings (A1 through A10) are the load-bearing claims.

**If you are evaluating the WOTS+C mode specifically:** `protocol-spec.md` (sections on WOTS+C and ERC compatibility), then `2b-pq-only-analysis.md`, then `wots-param-security-analysis.md`, then `protocol-spec-annex-b.md`.

**If you are evaluating the ECDSA mode specifically:** `protocol-spec.md` (section on ECDSA mode), then `2a-ecdsa-only-analysis.md`.

**If you are implementing a wallet:** all of the above, plus `derivation-path-analysis.md` and `protocol-spec-annex-a.md`.

## Status

Work in progress. The specification and analyses are actively maintained and changes should be expected as the design matures and feedback comes in. Treat the current documents as the best available reference, not as a frozen standard. Reference implementations live in separate repositories and are also under active development. 
 
## Roadmap
 
Areas of ongoing and upcoming work:
 
- Recovery implementation
- Few-time signatures (FTS)
- Hardware wallet and multisig support
- Multi-chain ephemeral keys account
- WOTS and FTS gas bumping strategies

## About

Maintained by [Riva Labs](https://riva.xyz). The protocol is the basis of NiceTry, a quantum-safe smart wallet. Security analyses were authored by [Conor Deegan](https://github.com/conor-deegan), a vital contributor to this repo. For questions or collaboration, open an issue.

