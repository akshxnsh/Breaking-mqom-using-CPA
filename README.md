# Breaking MQOM using CPA

Undergraduate B.Tech project (BTP): **Exploring Side-Channel Attacks on Standard Ciphers
— CPA Analysis of MQOM v2.1.** Guide: Dr. Debranjan Pal, LNMIIT Jaipur.

**Goal.** Recover the complete permanent secret witness `x` of MQOM v2.1 via a
CPA-based technique (success criterion `x_hat == x`), and establish the mathematical
conditions under which recovery is possible.

## Scientific integrity / scope

This is a **computer-only** study. It uses **no** physical hardware, measurement
equipment, real power/EM traces, or the official MQOM reference implementation. Every
"leakage" here is **synthetic**, generated from independent mathematical models under
**explicitly stated hypothetical leakage functions**. A successful simulated recovery
is a demonstration *under an assumed model* — it is **not** a demonstrated vulnerability
of any real MQOM implementation or device. Claims are tagged throughout:
`[Spec]` specification fact · `[Pub]` published result · `[Deduction]` our maths ·
`[Assumption]` simulation assumption · `[SynResult]` synthetic experiment result.

## Repository layout

```
gf256.py                     Independent GF(256) field (verified vs AES test vectors)
candidate_c/                 Part 1 — correction value Delta_x^(1) (suffix)
  model_c.py                 spec-derived model, synthetic leakage, vertical key-XOR CPA
  run_baseline.py            baseline recovery + complement-ambiguity + controls
  run_mismatch.py            model-mismatch / robustness + LRA degeneracy
  results_*.json             saved numeric results
candidate_b/                 Part 2 — compute_t1 Ahat.x (prefix, PRIMARY)
  model_b.py                 audit-derived model, synthetic leakage, horizontal CPA
  run_baseline.py            prefix recovery + c=g*x^-1 aliasing + x_j=0 self-detection + controls
  run_mismatch.py            monotone/non-monotone mismatch + non-monotone failure boundary
  results_*.json             saved numeric results
candidate_f/                 Part 2 — correlated-tree delta (prefix, BACKUP)
  model_f.py                 audit-derived model, second-order (mask, masked-value) CPA
  run_baseline.py            pooled-HW HW-class ceiling + bit-level envelope
  results_*.json             saved numeric results
RESEARCH_LOG.md              running lab log (tagged, maps to report chapters)
docs/
  part1_candidate_c.md       completed Part 1 write-up
  part2_prefix.md            completed Part 2 write-up (B primary + F backup)
report/                      LNMIIT LaTeX report scaffold (parked until conclusions solid)
```

## Research parts (committed one at a time)

- **Part 1 — Candidate C (correction value):** COMPLETE. Signed vertical key-XOR CPA
  recovers the 32-byte suffix of `x` under a monotone-leakage assumption, robust to
  weight mismatch; failure mode (non-monotone leakage) identified; the complement
  ambiguity of linear-XOR CPA characterised and resolved.
- **Part 2 — Prefix recovery (Candidate B horizontal / F second-order):** COMPLETE.
  Horizontal CPA on `compute_t1` recovers every non-zero prefix byte at 100% under a
  monotone-leakage assumption (~100 averaged signatures; ~19 horizontal positions suffice),
  robust to monotone weight mismatch and far more robust to non-monotone leakage than the
  Part-1 additive target. Wrong-key aliasing follows the `c = g*x^-1` law; `x_j = 0` is a
  self-detected structural blind spot deferred to MQ completion. Candidate F (second-order)
  is a scoped backup: pooled-HW recovers only `HW(delta)` (HW class), not the byte.
- **Part 3 — Full-vector assembly + MQ-system verification (+ fallback top-3 paths):** pending.

## Reproducing

```
python3 gf256.py                     # field self-test
python3 candidate_c/run_baseline.py  # Part 1 baseline
python3 candidate_c/run_mismatch.py  # Part 1 robustness
python3 candidate_b/run_baseline.py  # Part 2 prefix (B) baseline
python3 candidate_b/run_mismatch.py  # Part 2 prefix (B) robustness
python3 candidate_f/run_baseline.py  # Part 2 prefix (F) backup
```
All randomness is seeded. Requires numpy.
