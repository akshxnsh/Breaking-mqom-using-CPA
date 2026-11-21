# Part 2 — Prefix (bytes 0..15): Candidate B horizontal CPA (primary) + Candidate F second-order (backup)

**Status: COMPLETE.** Self-contained write-up of the Part-2 prefix study. Evidence tags:
[Spec] specification fact · [Audit] reference-implementation audit (commit b8879fe) ·
[Pub] published · [Deduction] our maths · [Assumption] simulation assumption ·
[SynResult] synthetic experiment. All leakage is synthetic; no physical measurement;
nothing here is a demonstrated vulnerability of a real device.

Code: `gf256.py`, `candidate_b/model_b.py`, `candidate_b/run_baseline.py`,
`candidate_b/run_mismatch.py`, `candidate_f/model_f.py`, `candidate_f/run_baseline.py`.
Results: `candidate_b/results_b_baseline.json`, `candidate_b/results_b_mismatch.json`,
`candidate_f/results_f_baseline.json`. Reproducible (fixed seeds).

Target: the 16-byte **prefix** `x[0..15]` of the gf256-short L1 witness (n = 48), which
Candidate C (Part 1) provably cannot reach (Delta_x = 0 on the prefix).

---

## 1. Why the prefix needs a different handle

[Spec] The correlated-tree construction forces `Delta_x[k] = 0` for the prefix coords
`k < 16`, so there is no public per-signature varying value there — Candidate C has no
handle. Two independent channels do touch the prefix:

- **Candidate B** — `compute_t1: t1_i = Ahat_i . x + bhat_i` [Audit, piop_default.c]. The
  PUBLIC multipliers `Ahat_i[r][j]` meet the fixed secret `x_j` many times within one
  trace (TRI_INF triangular structure: `~ mhat*(N-j)*2` byte-serial scalar multiplies per
  coord per signature). This is the **horizontal** variation axis and it exists for EVERY
  coordinate, prefix included. **Primary route.**
- **Candidate F** — `delta = FirstBits_128(x) = x[0..15]` enters the tree as
  `node3 = rseed XOR delta` alongside `node2 = rseed` [Audit, ggm_tree.c]. `rseed` is a
  fresh hidden mask, so only a **second-order** (mask, masked-value) channel exists.
  **Backup route.**

## 2. Candidate B — model and distinguisher

[Audit] The ext-by-base product is byte-serial (`gf256_mult_ref`, hi/lo byte), not SWAR-
packed, so byte-level leakage is not blurred. [Audit] With `USE_PIOP_CACHE`, `Ahat` and
`x` fixed, the identical intermediates recur every `Sign()`, so leakage can be
**vertically averaged across signatures** (effective noise `sigma/sqrt(n_sig)`).

[Assumption] Leakage of the secret-dependent product, per horizontal position:
`L_pos = HW( gf256_mult(x_j, a_pos) ) + N(0,sigma)`. The attacker predicts
`HW(gf256_mult(g, a_pos))` for each guess `g` and correlates over positions; it never
receives `x`, shares, or `acc_x` — leakage depends on `x_j` only through the real field
product (guards success-by-construction).

Modelling abundances: `positions/coord = mhat*(N-j)*2` with `mhat=24, N=48` ⇒ **1584
(j=15) … 2304 (j=0)** positions per coordinate per signature; multipliers are XOF output,
modelled uniform over GF(256).

## 3. Candidate B — key finding: identifiability is clean (and the one exception)

[Deduction] **No complement ambiguity** (unlike the additive suffix target of Part 1).
Field multiply by a fixed nonzero `a` is a bijection in the guess, and the wrong-key
correlation depends **only** on `c = g * x^{-1}`:
`rho(c) = corr_a( HW(a), HW(c*a) )`. The correct key is `c = 1` (rho = 1); a wrong key
ties only if `HW(c*a)` is affine in `HW(a)`, which holds for `c = 1` alone. So under full
multiplier coverage the true byte is the unique maximum.

[SynResult] Confirmed: across keys the `|rho|(c)` curve is key-independent (max std
`3.4e-2`); correct `c=1` ⇒ `|rho| = 1.000`; strongest aliases `c=0x02 (0.63)`,
`c=0x8D (0.60)`; **noiseless margin ceiling ≈ 0.37**.

[Deduction + SynResult] **The one structural exception: `x_j = 0`.** Then `x_j*a = 0` for
all `a` — a dead multiplicative channel — and the guess `g=0` is also constant, so CPA
cannot select it. This is **self-detected**: the zero byte's max `|rho|` collapses to
noise (mean **0.069**, p95 0.088) versus nonzero bytes (mean **0.998**, min 0.997), a
clean separation at a 0.30 flag threshold (100% detection). A detected zero byte (≤1–2 of
16 on average) is then pinned by the public MQ system in Part 3 — it is not a silent
error.

## 4. Candidate B — recovery results (matched HW)

[SynResult] `L = HW(x_j*a) + noise`; 40 independent keys; 100 signatures averaged.
Recovery reported over NON-ZERO bytes (x_j=0 is the structural case above).

| sigma (signal std ~1.4) | nonzero-byte recovery | 0-byte detection |
|---:|---:|---:|
| 0.0 / 0.5 / 1.0 / 2.0 / 4.0 / 8.0 | **100%** | 100% |

Positions-to-disclosure (coord 8, sigma = 2): **19 positions already give 100%** per byte
— horizontal abundance (1584–2304/coord) is far beyond what recovery needs. Negative
controls: all-multiplier-zero channel 0%, shuffled-label null 0% (top margin ~0);
matched contrast true 0.998 vs best-wrong 0.618 (margin 0.38).

## 5. Candidate B — robustness to leakage-model mismatch

[SynResult] Attacker always predicts plain HW; true device leakage generated under
several shapes; 30 keys, 100 sigs; nonzero bytes.

| generated leakage | nonzero recovery (sigma 0→8) | mean margin |
|---|---:|---:|
| matched HW | 100% | 0.37 → 0.32 |
| realistic weighted-HW (monotone) | 100% | 0.37 → 0.33 |
| non-monotone stress (one bit backwards) | 100% | **0.088** |

[Deduction] **Contrast with Part 1.** The additive XOR suffix target broke to 0% under
non-monotone leakage (perfect anti-correlation of a flipped bit). The **multiplicative**
horizontal target does not: multiplying by varying `a` spreads each secret bit across all
output bits, so one backwards bit only **shrinks the margin ~4×** (0.37 → 0.088) rather
than inverting the distinguisher. Recovery still holds given the real position abundance.

[SynResult] The shrunken margin does set a boundary. Single-trace, sigma = 4, starved
positions: matched HW reaches 100% by 512 positions; non-monotone reaches only 64% — the
~4× smaller margin needs ~order-of-magnitude more data. The "more data → wrong maximum"
failure of linear-GF maps (MAYO MDPI 2026; SDitH 2024/1882) did **not** appear under these
monotone/non-monotone shapes with HW prediction: added averaged signatures always
converged to the true byte (100% at n_sig ∈ {1,10,100,1000}).

## 6. Candidate F — second-order backup, and its honest ceiling

[Deduction] For a uniform byte mask `r` and pooled-HW leakage, the centered product of the
two leakages estimates `Cov(HW(r), HW(r XOR delta)) = 2 - HW(delta)/2`. This is a function
of **HW(delta) only** — it cannot separate bytes of equal Hamming weight, and there is no
public per-signature input to form a classical correlation. So pooled-HW F recovers the
**HW class** of each prefix byte (1 of 9), not the byte.

[SynResult] HW(delta) estimate is essentially exact (bias ~0, std 0.02–0.06; 100% HW-class
at sigma ≤ 2, stable from ~1000 signatures), but that leaves **~50 candidates/byte of
256** ⇒ **F alone cannot recover the prefix**, confirming its scoped role as a partial
backup. [SynResult] Under a **stronger per-bit** leakage assumption, the sign of each
per-bit covariance gives each delta bit ⇒ full-byte recovery 100% (sigma ≤ 2); this
delimits F's envelope but is not the realistic primary model.

## 7. Conclusion for Part 2

[SynResult] Under the physically-standard monotone-leakage assumption, **Candidate B
horizontal CPA fully recovers the 16-byte prefix of the MQOM v2.1 witness** in simulation:
every nonzero byte at 100% across a wide noise range from only ~100 averaged signatures
(indeed ~19 horizontal positions suffice), robust to monotone weight mismatch and far more
robust to non-monotone leakage than Part 1's additive target. The single structural
exception `x_j = 0` is detected, not silently wrong, and is completed by the public MQ
system in Part 3. Candidate F is a genuine but partial backup (pooled-HW ⇒ HW class only).

Combined with Part 1 (suffix via Candidate C), a CPA-based handle now exists for **all 48
bytes** of `x`. **Remaining (Part 3):** assemble `x_hat = prefix || suffix`, complete any
detected zero/aliased byte, and verify against the public MQ system `y_i = x^T A_i x +
b_i^T x`.

## 8. Report mapping
- Ch3 (Proposed Work): §1 prefix handle, §2 B model + attacker model, §6 F model.
- Ch4 (Simulation & Results): §3 identifiability + zero-byte, §4 recovery + controls, §5 mismatch, §6 F ceiling.
- Ch5 (Conclusions): §7.
