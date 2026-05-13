# Ephemeral Keys: A Quantum-Safe Smart Wallet Protocol

## Abstract

Ephemeral Keys is a protocol for quantum-safe smart accounts on Ethereum. The construction leverages account abstraction to rotate the authorizing signer commitment after every transaction, while the account address remains constant. This eliminates long-term public key exposure, the attack surface that Shor's algorithm exploits against ECDSA, without requiring any changes to Ethereum's protocol.

The primary signing scheme is FORS+C, a standalone hash-based few-time signature scheme used in SLH-DSA / SPHINCS+ with target-sum grinding. Security reduces to preimage resistance of Keccak-256, the few-time property means accidental key reuse degrades gracefully rather than catastrophically, and signature verification is economically viable onchain at roughly 47k gas.

## Motivation

Ethereum accounts are secured by ECDSA over the secp256k1 curve. The private key never appears onchain; only the public key or its hash is exposed when a transaction is signed. This design is secure against classical computers because computing a discrete logarithm over an elliptic curve group is believed to be computationally infeasible.

That assumption breaks under Shor's algorithm. A quantum computer with sufficient qubit fidelity and count can recover an ECDSA private key from a public key in polynomial time. Current expert estimates place a cryptographically relevant quantum computer, one capable of breaking 256-bit elliptic curve cryptography, at roughly 3 to 5 years away, with significant uncertainty in both directions. The threat is not immediate, but the preparation window is.

Upgrading Ethereum's signature infrastructure is a multi-year process requiring EVM opcode changes, new precompiles, wallet software updates, and ecosystem-wide coordination. Historical precedent from SHA-1 deprecation and early TLS migrations suggests that even after standardization, actual adoption takes years. Ephemeral Keys is an alternative available today: a smart account construction that achieves quantum safety without any dependency on Ethereum protocol changes, and without waiting for ecosystem convergence on a post-quantum standard.

### Threat Model Summary

We consider an adversary who can observe all onchain and mempool data and can perform Shor's algorithm to recover an ECDSA private key from an observed public key. The adversary cannot break preimage resistance or collision resistance of SHA-2 or Keccak-256. Even with access to a powerful Quantum Computer, which we assume the attacker has, the speedup obtained by Grover's algorithm, which is the one relevant to these hash functions, is quadratic, which is not enough to make breaking these primitives possible. Additionally, we assume the adversary cannot censor the Ethereum mempool indefinitely.

## Protocol Overview

The protocol defines a smart account conforming to ERC-4337 (Account Abstraction). The account exposes a single, stable address to the user. The current primary signing scheme is FORS+C; earlier ECDSA-rotation and WOTS+C-rotation schemes are retained and documented under [Past Signing Schemes](#past-signing-schemes).

**FORS+C scheme.** The account stores a 20-byte commitment derived from `(pkSeed, pkRoot)`, where `pkRoot` is the compression of the FORS+C public key. Each signature uses a fresh keypair: signing produces both a signature over the current UserOp and a commitment to the next keypair, which the contract writes atomically inside `validateUserOp`. Security reduces to preimage resistance of Keccak-256. Observing a signature in the mempool reveals nothing actionable to a quantum adversary, and accidental key reuse degrades gracefully rather than catastrophically. The signature is NIST security level 1 at the design target of one signature per key.

FORS+C in this protocol is standalone: there is no XMSS hypertree above. The public key is the FORS roots compression alone. This is the simplification that makes onchain verification economically viable; a full SLH-DSA / SPHINCS+ verify would cost an order of magnitude more gas. A dedicated domain separation byte distinguishes standalone FORS+C from SLH-DSA family members that share the same FORS primitive.

The protocol can be deployed as an ERC-4337 smart account and, separately, as an ERC-7579 validator module installable on any compliant modular account.

## Definitions and Notation

**`sk`** — Signing private key. Never stored or transmitted onchain.

**`pk`** — Signing public key corresponding to `sk`.

**`addr(pk)`** — Ethereum address derived from an ECDSA public key. The onchain signer identifier in the ECDSA past scheme.

**`H(pk)`** — Hash of a serialized public key. The onchain signer identifier in the WOTS+C past scheme.

**`pkSeed`** — 16-byte public seed. Tweak input to every hash call in FORS+C key generation, signing, and verification.

**`pkRoot`** — 16-byte compression of the FORS+C public key (Keccak hash of the `K-1` surviving FORS tree roots under the +C variant).

**`addr(pkSeed, pkRoot)`** — 20-byte commitment `keccak(pkSeed ‖ pkRoot)[12:32]`. The onchain signer identifier in FORS+C mode.

**`sk_i`, `pk_i`** — The signing material at index `i`. Derived deterministically from the user's seed.

**`seed`** — The user's master secret. Stored only on the client device. All key material is derived from it.

**`K`** — Number of FORS trees per keypair. Under +C, only `K-1` are computed and transmitted.

**`A`** — FORS tree height. Each tree has `2^A` leaves.

**`mdT`** — `A`-bit message-digest field selecting one leaf in tree `t`.

**`counter`** — 16-byte grinding nonce iterated by the signer until the `K`-th `mdT` field is zero.

**`n`** — Hash truncation length in bytes. Common to FORS+C and WOTS+C parameterizations.

**`w`** — Winternitz parameter (WOTS+C only). Controls the tradeoff between chain length and signature size.

**`l`** — Number of hash chains in a WOTS+C keypair. A function of `n` and `w`.

**`sig`** — A signature over the ERC-4337 UserOp hash. Size depends on the scheme.

**`ephemeral key`** — Any keypair valid for at most one signing operation in the design target. Applies to all schemes.

### FORS+C Parameters

FORS+C is parameterized by `n` (truncated hash length in bytes), `K` (number of trees), and `A` (tree height). A signature consists of `R`, `pkSeed`, `K-1` (secret-key, auth-path) pairs of `n + A·n` bytes, and the grinding counter. The **C** in FORS+C stands for **Compression**: the signer iterates the counter until the resulting message digest has its `K`-th `A`-bit field equal to zero, allowing the verifier to skip that entire tree and dropping one auth path from the signature.

Current selection is `n = 16`, `K = 26`, `A = 5`. Concrete numbers for signature size, verifier gas, and signer hashing cost are given in [FORS+C → Parameters](#parameters).

### WOTS+C Parameters

WOTS+C is parameterized by `n` and `w`. The number of chains `l` is determined by `n` and `w`. The **C** is the same compression trick: the signer brute-forces a counter so the message digest produces a fixed, known checksum, allowing the checksum chains to be dropped from the signature. Past-scheme deployed configuration is `n = 16`, `w = 32`, `l = 26`, target sum 403, signature 468 bytes.

## Account Architecture

### Smart Account Contract Layout

An Ephemeral Keys account is a non-upgradeable smart contract. A single storage slot tracks the current signer identifier: `addr(pkSeed_i, pkRoot_i)` for FORS+C, or the historical commitments `addr(pk_i)` and `H(pk_i)` for the ECDSA and WOTS+C past schemes respectively. Advancing the key after each transaction is an atomic update to that slot.

### ERC-7579 Module Compatibility

The validation logic is also packaged as a standalone ERC-7579 validator module. Users with an existing compliant modular account can install the Ephemeral Keys validator without deploying a new account. The module stores its own per-account key state, keyed by account address as the outermost mapping key to satisfy ERC-7562 storage access rules.

### Validation Flow

When `validateUserOp` is called by the EntryPoint in FORS+C mode:

1. Call the FORS+C verifier as a pure `recover(sig, userOpHash)`. The verifier reconstructs `(pkSeed, pkRoot)` from the signature and returns `addr(pkSeed, pkRoot)`.
2. Compare the returned address against the stored signer identifier. If equal, return `SIG_VALIDATION_SUCCESS`.
3. Rotate atomically: overwrite the stored value with `addr(pkSeed', pkRoot')` for the next keypair, supplied by the user in the UserOp calldata. Rotation occurs during validation to minimize the risk of an authorized transaction being finalized without the key advancing.

The past-scheme validation flows are documented under [Past Signing Schemes](#past-signing-schemes).

### Key Derivation

In all schemes, key material is derived deterministically from `seed` using a BIP-44 path indexed by `idx`. The user never needs to store individual keys; the seed alone is sufficient to regenerate any key at any index. For FORS+C, the leaf entropy is expanded into `pkSeed` and the per-leaf secret-key material via tagged Keccak domain separation. The full per-scheme derivation specification lives in [`derivation-path-analysis.md`](./derivation-path-analysis.md).

## FORS+C

### Validation

The FORS+C verifier is exposed as a pure `recover(sig, userOpHash)` function. Internally it:

1. Hashes the UserOp digest with `pkSeed`, `R`, the FORS+C domain byte, and the counter to produce `dVal`.
2. Asserts the `K`-th `A`-bit field of `dVal` is zero (the +C grinding constraint). If not, returns `address(0)`.
3. Opens `K-1` FORS trees, deriving leaf hashes from the `K-1` supplied secret-key fragments and climbing each auth path to obtain `K-1` roots.
4. Compresses the roots into `pkRoot` via a single Keccak call over the concatenated roots and a fresh ADRS.
5. Returns `addr(pkSeed, pkRoot)`.

The account contract compares the returned address against the stored signer and rotates atomically on match, as in [Validation Flow](#validation-flow).

### Security Properties

Observing a FORS+C signature in the mempool reveals nothing actionable to a quantum adversary. There is no public key that can be inverted; the signature itself leaks no material that allows key recovery under any known algorithm, classical or quantum. The residual mempool vulnerability present in the ECDSA design is eliminated.

Unlike WOTS+C, FORS+C is a few-time scheme rather than one-time. Each FORS+C key has graceful degradation under reuse: at the current parameters (`K=26, A=5`) the classical forgery hardness as a function of the number of signatures `q` produced under one key is:

| q | Bits (classical) |
|---|------------------|
| 1 | 128              |
| 2 | 104              |
| 3 | 89               |
| 4 | 78               |
| 5 | 70               |

The design target is `q = 1` and the protocol enforces single-use through atomic rotation. The few-time property is a safety margin: in the failure modes that would expose a WOTS+C signer to immediate classical forgery (reverted transaction, dropped UserOp, replacement transaction), a FORS+C signer remains unforgeable.

### Key Rotation

Key rotation is done inside `validateUserOp`. No authorized transaction can be finalized without advancing the key, reducing the risk of user error.

If one of the UserOps in a bundle reverts, the rotation still occurs. This is consistent with ERC-4337, where individual UserOps can revert while the parent transaction succeeds.

If a transaction fails entirely (wrong nonce, insufficient gas) and is never included onchain, the user can safely resign with the same FORS+C key, since reuse is not immediately catastrophic. The wallet MUST track the per-key reuse count and enforce a bounded budget. Recommended policy:

- `q ≤ 2` is the normal-operation envelope, at NIST Level 1 security or above (≥ 104 bits classical). Replacement-transaction flows fall here.
- `q ≤ 5` is the maximum permitted under degraded security (≥ 70 bits classical) for emergency reuse.
- Beyond `q = 5`, the wallet MUST refuse to sign with that key.

Wallets SHOULD burn private key material after the per-key budget is reached, and SHOULD NOT expose signing primitives that allow exceeding the budget.

### Parameters

Current selection: `n = 16`, `K = 26`, `A = 5`.

| Metric                       | Value         |
|------------------------------|---------------|
| Signature size               | 2,448 bytes   |
| Verifier gas                 | ~47,000       |
| Signer hashes per signature  | ~2,400        |
| Hash truncation              | 16 bytes      |
| Domain separation byte       | `0xFD`        |

The set is current as of the latest protocol revision and may evolve as the design and tooling mature. The signer-hash count is dominated by FORS tree construction (`K · 2^A` leaf PRF calls plus internal nodes) and the grinding-counter expectation (`~2^A` retries on average). At `K = 26, A = 5` this is feasible on hardware wallets.

### Multi-Wallet Compatibility

A FORS+C account rotates signing keys after each use. If two wallets share the same seed and derivation path, they generate identical key sequences, and independent advancement of the epoch counter on either wallet risks reusing the same few-time key beyond what the per-key budget can absorb. The mitigation is the same as for WOTS+C: each wallet derives keys under a wallet-specific salt that gives non-overlapping key streams while keeping the mnemonic as a complete backup. See [Annex B](./protocol-spec-annex-b.md) for the mechanism.

The few-time property of FORS+C makes the failure mode less brittle than WOTS+C (a single accidental cross-wallet reuse is recoverable rather than immediately catastrophic), but seed-derived wallet separation is still required.

## Past Signing Schemes

Both schemes below were primary signing schemes in earlier revisions of the protocol. They remain deployable through the same factory and are documented here for completeness and historical reference. New deployments should use FORS+C unless a specific reason exists to prefer one of these.

### ECDSA

The initial design used ECDSA over secp256k1 with rotation after every transaction. The account stored `addr(pk_i)`. Validation:

1. Recover the signer address from the UserOp signature via `ecrecover`. Compare against the stored `addr(pk_i)`.
2. If equal, return `SIG_VALIDATION_SUCCESS`.
3. Rotate atomically: overwrite the stored value with `addr(pk_{i+1})`, supplied by the user in the UserOp.

Security relied on the rotation race: each key was retired before a quantum adversary could recover it from the observed public key. The residual vulnerability was the mempool window between broadcast and inclusion, during which a sufficiently fast quantum adversary could in principle recover `sk_i` and front-run the user. The intended mitigation was private mempool relays. Key reuse under ECDSA is not catastrophic against a classical adversary; under reuse the protocol's quantum-safety guarantees simply collapse to ordinary ECDSA semantics.

### WOTS+C

The second iteration replaced ECDSA with WOTS+C, a hash-based one-time signature scheme. The account stored `H(pk_i)`. Validation:

1. Call the WOTS+C verifier to reconstruct `pk_i` from the signature and the UserOp hash. Assert `H(pk_i)` matches the stored value.
2. If equal, return `SIG_VALIDATION_SUCCESS`.
3. Rotate atomically: overwrite the stored value with `H(pk_{i+1})`, supplied by the user in the UserOp.

Security reduced to preimage resistance of Keccak-256; observing a WOTS+C signature gave no advantage to a quantum adversary, and the mempool window was eliminated. The cost was reuse fragility: signing two different messages with the same WOTS+C key leaks enough chain information to allow classical forgery, making accidental reuse immediately catastrophic. Softening this failure mode is the principal reason FORS+C was introduced as the primary scheme. Deployed parameters: `n = 16`, `w = 32`, `l = 26`, target sum 403, signature 468 bytes, verifier gas ~93,000.

## ERC Compatibility

### ERC-4337 Conformance

All Ephemeral Keys account contracts implement the `IAccount` interface defined by ERC-4337. A notable deviation from common implementations is that the contracts write state during `validateUserOp`: the signer commitment is rotated atomically at validation time rather than during execution. This is intentional and does not break ERC-4337 conformance, but has two consequences worth documenting:

- **Revert behavior:** if the inner transaction reverts, the key rotation has already occurred. A failed transaction consumes a key just as a successful one does. Under FORS+C this is recoverable through bounded reuse (see [Key Rotation](#key-rotation)); under WOTS+C it is not.
- **Bundler compatibility:** bundlers simulate `validateUserOp` before inclusion. Since state written during simulation is not visible to subsequent simulations in the same bundle, bundlers must not include more than one pending UserOp per sender in a bundle. This is already standard bundler behavior and is not a new constraint introduced by this protocol.

All contracts access only their own storage during `validateUserOp`, satisfying ERC-7562 storage access rules.

#### Current adoption of private mempools

On many L2s bundlers already use private mempools, so the trust assumption for the ECDSA past scheme is restricted to the mempool owner. On Ethereum L1 there is an effort toward a shared mempool, but it is not yet used by every bundler. This concern does not apply to FORS+C or WOTS+C, where mempool observation is not actionable.

### ERC-7579 Module Interface

The validation logic for all schemes is additionally packaged as an ERC-7579 `IValidator` module. Users with an existing compliant modular account can install the Ephemeral Keys validator without deploying a new account. Module state is keyed by account address as the outermost mapping key, satisfying ERC-7562 requirements for module storage access.

### EIP-1271 Limitations

None of the Ephemeral Keys signing schemes implement EIP-1271 directly. For FORS+C and WOTS+C the incompatibility is fundamental: signature verification mutates state (the rotation), and EIP-1271 requires a view function. For the ECDSA past scheme it is a current limitation rather than a fundamental one. The proposed workaround is a dedicated permit signer with its own isolated key stream and rotation policy, detailed in [Annex A](./protocol-spec-annex-a.md).

### ERC-7702 Relevance

ERC-7702 allows an EOA to delegate execution to a smart contract implementation. If adopted, it could allow users to use Ephemeral Keys validation logic without deploying a new account or transferring assets to a new address. The protocol's contract interfaces are compatible with ERC-7702 delegation in principle, but a key piece is missing: the original EOA signer can always sign a transaction to change the EOA implementation. Full ERC-7702 compatibility additionally requires what is described in [EIP-7851](https://eips.ethereum.org/EIPS/eip-7851) (EOA deactivation).

## Reference Implementation

[NiceTry](https://github.com/RivaLabs-Core/NiceTry) is the reference implementation of the Ephemeral Keys protocol. It provides the Solidity contracts for the FORS+C smart account, the WOTS+C and ECDSA past-scheme contracts, and the corresponding ERC-7579 validator modules.
