# MQOM v2.1 CPA — Research Log (working notes, feeds the final report)

Plain lab-notebook for the research. NOT the report. Entries are tagged by evidence
category: [Spec] specification fact · [Pub] published result · [Deduction] our maths ·
[Assumption] simulation assumption · [SynResult] synthetic experiment result.
Each entry notes which report chapter it will feed.

Goal (fixed): recover the full permanent witness x of MQOM v2.1 via a CPA-based
technique, success = x_hat == x. Computer-only; synthetic leakage; no hardware, no real
implementation. Fallback if no clean recovery: evidence-grounded top-3 high-potential
paths.

Candidate working order: C (suffix) -> B / F (prefix) -> assemble full x.

---

## Setup / infrastructure  (feeds Ch4 methodology)
- Independent GF(256) implemented (AES field, poly 0x11B), verified against AES test
  vectors (0x57*0x83=0xC1; 0x53,0xCA inverses; xtime(0x80)=0x1B) and against a slow
  reference multiply on 5000 random pairs. File: `gf256.py`. [Deduction/infra]
- gf256-short L1 params: n=48 GF(256) coords; lambda/8 = 16 -> prefix bytes 0..15,
  suffix bytes 16..47 (32 attackable). [Spec, Table 6]

## Candidate C — correction value Delta_x^(1)   (feeds Ch3 model + Ch4 results)

### Spec basis [Spec] (MQOM v2.1 sec2.1.3 / Eq.4 / sec2.5.6 / Alg.11)
- Delta_x = x XOR acc_x,  acc_x = sum_i xbar_i (sum of fresh per-signature shares).
- Suffix coords k>=16: acc_x[k] = x[k] XOR Delta_x^(1)[k], with Delta_x^(1)[k] PUBLIC
  and varying per signature. Prefix coords k<16: Delta_x forced 0 -> no varying data
  -> no C handle (that is Candidate F).

### Attacker model / leakage [Assumption]
- Known to attacker: public Delta_x^(1)[k] per signature; synthetic leakage of the
  SECRET operand acc_x[k]. Hidden: x[k], acc_x[k].
- Baseline leakage: L = HW(acc_x[k]) + N(0,sigma) = HW(x[k] XOR Delta_x^(1)[k]) + noise.
  Attacker never receives acc_x or x; guards against success-by-construction.
- Model acc_x suffix as fresh uniform GF(256) (sum of many fresh shares is uniform).

### KEY FINDING — complement ambiguity of linear-XOR CPA  [Deduction + SynResult]
- Under ANY affine-in-bits leakage phi, the complement key g'=x XOR 0xFF predicts
  phi(x_bar XOR d) = C - phi(x XOR d): perfectly ANTI-correlated with true leakage.
  => |Pearson| ties x with x XOR 0xFF (irreducible 2-way / 1-bit ambiguity).
  => weighted-HW does NOT fix it (still affine). [Deduction]
- Confirmed in sim: true key 0xcd vs complement 0x32 both |corr|=0.8229 (tied).
  |corr|-CPA => ~50% per byte, full 32-byte recovery = 0% even at sigma=0. [SynResult]
- RESOLUTION: use SIGNED correlation under the stated "leakage grows with HW" polarity:
  true key -> +0.8229, complement -> -0.8229 (separated). [Deduction]
- Residual: polarity is a SINGLE GLOBAL sign (same all bytes) => at most 2 global
  candidates for whole suffix, trivially disambiguated by the public MQ system; NOT
  2^32. So suffix recovery is effectively unconditional once polarity fixed. [Deduction]

### Recovery results — signed vertical key-XOR CPA  [SynResult]
(L = HW(acc_x)+noise; 30 independent keys; 4000 signatures)
- Full 32-byte suffix recovery = 100% at sigma in {0,0.5,1,2,4}; mean rank 0.00.
- Traces-to-disclosure at sigma=2.0 (noise > signal std ~1.41): 100 sig -> 94% per byte;
  200 sig -> 100%. Vertical averaging beats noise (SNR ~ sqrt(n_sig)).
- Negative controls: prefix coord (Delta_x=0) true-key rank 153 (no handle);
  shuffled leakage rank 250, margin ~0 (collapses); matched suffix rank 0,
  correct 0.566 vs best-wrong 0.443, margin 0.12.
- Files: `candidate_c/model_c.py`, `candidate_c/run_baseline.py`,
  `candidate_c/results_c_baseline.json`. Reproducible (fixed seeds).

### Model-mismatch / robustness  [SynResult + Deduction]  (attacker always assumes HW)
(signed HW-CPA; true device leakage = sum_k w_k bit_k(acc_x)+noise, standardised std;
 20 keys, 3000 sig; file: `candidate_c/run_mismatch.py`, `results_c_mismatch.json`)
- Robust to MONOTONE weight mismatch: HW / weighted_mild / weighted_strong -> 100% full
  suffix recovery at sigma=1,2. weighted_uniform -> 95% at sigma=2. dominant_bit -> 80%
  full / 99.2% per-byte at sigma=2 (graceful degradation).
- Fails under NON-MONOTONE leakage (one bit with negative weight): 0% recovery, mean
  rank ~4.4. Clear, characterised failure boundary. [SynResult]
- LRA / linear-regression distinguisher is DEGENERATE on this bare-XOR target: R^2 across
  all 256 guesses identical to 1e-16 (std 1.4e-16). Because acc_x=g XOR d, the 8-bit
  linear basis span{1,bits(g^d)} = span{1,bits(d)} is independent of g -> no distinguishing
  power. So the non-monotone failure is NOT repairable by switching to LRA. [Deduction+SynResult]

### Status / what it does NOT establish
- [SynResult] Under a monotone leakage assumption (physically the norm: all bits add
  same-sign power), signed HW-CPA fully recovers the 32-byte SUFFIX of x, robustly to
  weight mismatch and noise. Demonstration under an assumed model, NOT a physical
  vulnerability. Failure mode (non-monotone leakage) is identified and bounded.
- PART 1 (Candidate C) COMPLETE.

## Candidate B — compute_t1 horizontal CPA (PREFIX primary)   (feeds Ch3 model + Ch4 results)

### Spec/Audit basis [Spec][Audit] (MQOM v2.1, piop_default.c compute_t1; commit b8879fe)
- t1_i = Ahat_i . x + bhat_i per signature. Ahat PUBLIC (from mseed_eq in pk), x SECRET,
  both FIXED across sigs; USE_PIOP_CACHE => identical intermediates recur every Sign()
  => VERTICAL AVERAGING across sigs (eff noise sigma/sqrt(n_sig)).
- Ext-by-base product is byte-serial (gf256_mult_ref hi/lo), NOT SWAR => byte leakage not
  blurred. TRI_INF triangular => x_j meets ~mhat*(N-j)*2 public multipliers/sig: 1584
  (j=15) .. 2304 (j=0). This HORIZONTAL axis exists for EVERY coord incl. prefix.
- Reaches the prefix (bytes 0..15) that Candidate C cannot (Delta_x=0 there). Primary route.

### Attacker model / leakage [Assumption]
- Known: PUBLIC multipliers a=Ahat_i[r][j] per position; synthetic leakage of product x_j*a.
  Hidden: x_j. Predict HW(gf256_mult(g,a)), correlate over positions. Leakage depends on
  x_j only via the real field product (guards success-by-construction).

### KEY FINDING — clean identifiability + the c=g*x^-1 aliasing law  [Deduction + SynResult]
- NO complement ambiguity (unlike additive suffix). Field mult by fixed a is a bijection
  in g; wrong-key corr depends ONLY on c=g*x^-1: rho(c)=corr_a(HW(a),HW(c*a)); correct
  c=1 is the unique max (a wrong c ties only if HW(c*a) affine in HW(a), i.e. c=1). [Deduction]
- Confirmed: |rho|(c) key-independent (max std 3.4e-2); c=1 -> |rho|=1.000; top aliases
  c=0x02 (0.63), c=0x8D (0.60); noiseless margin ceiling ~0.37. [SynResult]
- STRUCTURAL EXCEPTION x_j=0: x_j*a=0 for all a (dead channel) and g=0 is constant => not
  recoverable. SELF-DETECTED: zero-byte max|rho| mean 0.069 (p95 0.088) vs nonzero mean
  0.998 (min 0.997); clean split at 0.30 threshold (100% detection). Completed by MQ system
  in Part 3 — not a silent error. [SynResult]

### Recovery results — horizontal CPA  [SynResult]
(L=HW(x_j*a)+noise; 40 keys; 100 sigs averaged; recovery over NON-ZERO bytes)
- NON-ZERO prefix byte recovery = 100% at sigma in {0,0.5,1,2,4,8} (signal std ~1.4).
  Full raw 16-byte rate dips only via occasional x_j=0 (self-detected).
- Positions-to-disclosure (coord 8, sigma=2): 19 positions already 100% per byte; real
  abundance 1584-2304/coord far exceeds the need.
- Negative controls: all-multiplier-zero channel 0%; shuffled-label null 0% (top margin ~0);
  matched contrast true 0.998 vs best-wrong 0.618 (margin 0.38).
- Files: candidate_b/model_b.py, run_baseline.py, results_b_baseline.json. Seeded.

### Model-mismatch / robustness  [SynResult + Deduction]  (attacker always predicts HW)
(30 keys, 100 sigs; file candidate_b/run_mismatch.py, results_b_mismatch.json)
- matched HW & realistic weighted-HW (monotone): 100% nonzero recovery, margin ~0.37.
- NON-MONOTONE stress (one bit backwards): STILL 100% recovery but margin collapses to
  0.088 (~4x). CONTRAST with Part-1 XOR target which broke to 0%: the MULTIPLICATIVE
  (nonlinear) horizontal target spreads each secret bit across all output bits, so a
  backwards bit shrinks the margin rather than inverting the distinguisher. [Deduction]
- Boundary (single-trace, sigma=4, starved positions): matched HW hits 100% by 512
  positions; non-monotone only 64% — ~order-of-magnitude more data needed. "More data ->
  wrong max" (MAYO 2026 / SDitH 2024-1882) did NOT appear with HW prediction under these
  shapes: added sigs always converged to the truth. [SynResult]

### Status
- [SynResult] Under monotone leakage, horizontal CPA fully recovers the 16-byte PREFIX;
  x_j=0 detected + deferred to MQ completion. Demonstration under an assumed model, NOT a
  physical vulnerability. PART 2 Candidate B COMPLETE.

## Candidate F — correlated-tree delta second-order CPA (PREFIX backup)  (feeds Ch3/Ch4)

### Spec/Audit basis [Spec][Audit] (blc_default.c delta=FirstBits(x); ggm_tree.c)
- node2=rseed (fresh mask/sig), node3=rseed^delta (masked value); rseed hidden/refreshed
  => NO first-order handle; only SECOND-ORDER (mask, masked-value) channel.

### KEY FINDING — pooled-HW F recovers HW(delta) ONLY  [Deduction + SynResult]
- Centered product estimates Cov(HW(r),HW(r^delta)) = 2 - HW(delta)/2: a function of
  HW(delta) ONLY. No public per-sig input => no classical CPA handle. => recovers the HW
  CLASS (1 of 9), not the byte. [Deduction]
- Confirmed: HW(delta) est bias ~0, std 0.02-0.06, 100% HW-class at sigma<=2, stable from
  ~1000 sigs. ~50 candidates/byte of 256 remain => F ALONE cannot recover the prefix. [SynResult]
- Bit-level second-order (STRONGER assumption): sign of per-bit cov gives each delta bit =>
  full-byte 100% (sigma<=2). Delimits F's envelope; not the realistic primary model. [SynResult]
- Files: candidate_f/model_f.py, run_baseline.py, results_f_baseline.json. Seeded.
- PART 2 Candidate F (backup) COMPLETE. B is the flagship prefix route; F is the scoped backup.

## Open threads / next decisions
- [x] C baseline recovery + complement-ambiguity finding.
- [x] C model-mismatch / robustness + LRA degeneracy.
- [x] PART 2: Prefix (bytes 0..15): Candidate B horizontal CPA (primary, full recovery) +
      Candidate F 2nd-order CPA (backup, HW-class only). B chosen as flagship.
- [ ] PART 3: Assemble full x = prefix || suffix; complete detected zero/aliased bytes;
      verify via public MQ system y_i = x^T A_i x + b_i^T x. Fallback: top-3 paths if no
      clean full recovery.

## Report mapping (for later)
- Ch2 Literature: verified refs already compiled in Rev-B assessment + literature-notes.md.
- Ch3 Proposed Work: candidate taxonomy, prefix/suffix split, leakage taxonomy, CPA variants.
- Ch4 Results: GF(256) validation; Candidate C complement-ambiguity finding + recovery
  tables + controls; Candidate B horizontal CPA prefix recovery + c=g*x^-1 aliasing law +
  x_j=0 self-detection + mismatch; Candidate F HW-class ceiling; (pending) full-vector assembly.
- Ch5 Conclusions: C suffix recovered under HW model; identifiability lesson; full-x path.
- LaTeX scaffold already built under `report/` (LNMIIT template) — parked until conclusions solid.
