# Part 1 — Candidate C: Correction-Value Vertical Key-XOR CPA

**Status: COMPLETE.** Self-contained write-up of the Candidate C study. Evidence tags:
[Spec] specification fact · [Pub] published · [Deduction] our maths · [Assumption]
simulation assumption · [SynResult] synthetic experiment. All leakage is synthetic; no
physical measurement; nothing here is a demonstrated vulnerability of a real device.

Code: `gf256.py`, `candidate_c/model_c.py`, `candidate_c/run_baseline.py`,
`candidate_c/run_mismatch.py`. Results: `candidate_c/results_c_baseline.json`,
`candidate_c/results_c_mismatch.json`. Reproducible (fixed seeds).

---

## 1. Target and why it is a valid CPA point

[Spec] (MQOM v2.1, §2.1.3 / Eq. 4 / §2.5.6 / Alg. 11). The witness is additively shared;
the correction value is

    Delta_x = x XOR acc_x,     acc_x = sum_i xbar_i   (sum of fresh per-signature shares).

For the serialized suffix coordinates k >= lambda/8 (= 16 at L1), the correction
Delta_x^(1)[k] is **public** (in the signature) and **varies per signature**, and

    acc_x[k] = x[k] XOR Delta_x^(1)[k].

The prefix coords k < 16 have Delta_x[k] = 0 by the correlated-tree construction -> no
varying public data -> **no Candidate-C handle** (that is Candidate F). So Candidate C
targets the 32-byte suffix x[16..47] of the gf256-short L1 key (n = 48).

This is a genuine CPA point: a fixed secret x[k] meets known, per-signature-varying
public data Delta_x^(1)[k]. It is the classic key-XOR (key-additive) setup, as in the
AES first round before the S-box — but **linear** (no S-box), hence weaker selectivity.

## 2. Attacker model (guards against success-by-construction)

- Known to attacker: public Delta_x^(1)[k] per signature; synthetic leakage of the
  **secret** operand acc_x[k].
- Hidden from attacker: x[k], acc_x[k].
- Baseline leakage [Assumption]: L = HW(acc_x[k]) + N(0,sigma) = HW(x[k] XOR Delta_x^(1)[k]) + noise.
- The attacker never receives acc_x or x; it must distinguish x[k] among 256 hypotheses
  by correlation alone. The public Delta_x is the CPA *data*, never the leakage itself.

## 3. Key finding: the complement ambiguity of linear-XOR CPA

[Deduction] For a bare-XOR target under **any affine-in-bits** leakage phi, the complement
key g' = x XOR 0xFF predicts phi(x_bar XOR d) = C - phi(x XOR d): perfectly anti-correlated
with the true leakage. Therefore |Pearson| **cannot separate x from x XOR 0xFF** (an
irreducible 1-bit, two-way ambiguity). This also means weighted-HW does not help — it is
still affine.

[SynResult] Confirmed: true key 0xCD and complement 0x32 both give |corr| = 0.8229 (tied).
Absolute-correlation CPA therefore gives ~50% per byte and **0% full 32-byte recovery even
at sigma = 0**.

[Deduction] **Resolution:** use the **signed** correlation under the stated "leakage grows
with Hamming weight" polarity — true key -> +rho, complement -> -rho. The complement is the
*most negative* hypothesis, so argmax of signed correlation returns x.
Residual: polarity is a single global sign (same for all bytes), so at most **2 global
candidates** for the whole suffix, trivially disambiguated by the public MQ system — not
2^32. Under the monotone-leakage assumption, suffix recovery is effectively unconditional
once polarity is fixed (non-monotone leakage is the bounded exception — see §5).

## 4. Recovery results (signed vertical key-XOR CPA)

[SynResult] L = HW(acc_x) + noise; 30 independent keys; 4000 signatures.

| sigma (HW units; signal std ~1.41) | per-byte | full 32-byte suffix | mean rank |
|---:|---:|---:|---:|
| 0.0 / 0.5 / 1.0 / 2.0 / 4.0 | 100% | **100%** | 0.00 |

Traces-to-disclosure (sigma = 2.0): 100 signatures -> 94% per byte; **200 signatures ->
100%**. Vertical averaging across signatures suppresses noise (SNR ~ sqrt(n_sig)).

Negative controls: prefix coord (Delta_x = 0, no varying data) -> true-key rank 153
(no handle); shuffled leakage vs delta -> rank 250, top margin ~0 (collapses); matched
suffix coord -> rank 0, correct 0.566 vs best-wrong 0.443 (margin 0.12).

## 5. Robustness to leakage-model mismatch

[SynResult] Attacker always assumes plain HW; true device leakage = sum_k w_k bit_k(acc_x)
+ noise, standardised; 20 keys, 3000 signatures.

| true leakage shape | full-suffix @ sigma=1 | full-suffix @ sigma=2 |
|---|---:|---:|
| HW / weighted-mild / weighted-strong | 100% | 100% |
| weighted-uniform | 100% | 95% |
| dominant-bit | 100% | 80% |
| non-monotone (one bit flipped) | 0% | 0% |

[Deduction + SynResult] Two robustness facts:
1. Signed HW-CPA is **robust to any monotone weight mismatch** (recovery holds; graceful
   degradation only when one bit dominates at high noise). It **fails only under
   non-monotone leakage** (a bit leaking "backwards") — a clearly bounded failure mode.
2. The usual robustness tool, **LRA / linear-regression**, is **degenerate on this
   bare-XOR target**: R^2 is identical across all 256 guesses to 1e-16 precision, because
   acc_x = g XOR d makes the linear bit-basis span{1, bits(g^d)} = span{1, bits(d)}
   independent of g. So the non-monotone failure cannot be repaired by switching to LRA; a
   *nonlinear* basis or target would be required.

## 6. Conclusion for Part 1

[SynResult] Under the physically-standard assumption of monotone leakage, a **signed
vertical key-XOR CPA fully and robustly recovers the 32-byte suffix of the MQOM v2.1
witness x** in simulation, needing on the order of a few hundred signatures at realistic
noise. The result is a demonstration under an explicitly stated leakage model, not a
physical vulnerability; its failure mode (non-monotone leakage, which no linear-regression
distinguisher can repair) is identified and bounded.

**Remaining for full x:** the 16-byte prefix x[0..15] (Candidate F / B — Part 2), then
assembly and MQ-system verification (Part 3).

## 7. Report mapping
- Ch3 (Proposed Work): §1 target, §2 attacker model, §3 distinguisher.
- Ch4 (Simulation & Results): §3 ambiguity finding, §4 recovery tables + controls, §5 mismatch.
- Ch5 (Conclusions): §6.
