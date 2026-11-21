# Part 3 — Full-vector assembly + MQ-system verification

**Status: COMPLETE — primary objective met.** CPA-based recovery of the complete
48-byte witness `x` with `x_hat == x`. Evidence tags: [Spec] · [Audit] · [Pub] ·
[Deduction] · [Assumption] · [SynResult]. All leakage synthetic; no physical
measurement; not a vulnerability of any real device.

Code: `assembly/mq_system.py`, `assembly/assemble.py`, `assembly/run_full_recovery.py`.
Results: `assembly/results_full_recovery.json`. Reproducible (fixed seeds).

---

## 1. What Part 3 does

Parts 1–2 recover the two halves of `x` by CPA:
- **suffix** `x[16..47]` — Candidate C signed vertical key-XOR CPA (Part 1);
- **prefix** `x[0..15]` — Candidate B horizontal CPA (Part 2).

Two residual ambiguities remain, by construction, that CPA alone does not fix:
1. [Deduction] a **single global polarity bit** on the suffix (`sigma_hat` vs
   `sigma_hat XOR 0xFF`) — the leakage sign of Part 1;
2. [Deduction] self-detected **`x_j = 0` prefix bytes** — a dead multiplicative channel
   in Candidate B, flagged (not silently wrong) by a collapsed `max|rho|`.

Part 3 resolves both with the **public MQ system**, then certifies the assembled vector.

## 2. The public MQ relation (verifier/completer, never recoverer)

[Spec] The public key fixes a multivariate-quadratic map and its image:
`y_i = x^T A_i x + b_i^T x`, `i = 1..m`, over GF(256); gf256-short L1: `n = 48`,
`m = 48`. Modelled independently in `mq_system.py` (`A_i` upper-triangular, uniform).

[SynResult] It is a **sharp certifier**: the true `x` satisfies all 48 equations; a
vector wrong in even one byte satisfies **0/48** (the quadratic coupling cascades a single
error across all equations); a random vector satisfies ~`m/256`. So a false certification
has probability ~`256^-m` — effectively zero.

**Integrity.** Algebra is used ONLY to (a) pick the global polarity, (b) complete the few
flagged zero bytes, and (c) certify. The 48 bytes themselves are recovered by CPA. The MQ
system never substitutes for the distinguisher.

## 3. Completion + verification procedure

[Deduction] Candidate set = {2 polarities} × {`256^u` fills of the `u` flagged zero
bytes}. `u` is 0 for most keys, occasionally 1, rarely ≥2 (`P(u≥2) ~ 0.2%`). Each
candidate is checked against the whole MQ system (batched, chunked `mq_eval_batch`); the
**unique** candidate satisfying all `m` equations is the certified `x_hat`. Early structural
fact (§2) guarantees uniqueness: no wrong polarity or wrong fill can satisfy the system.

## 4. Results — exact full-vector recovery

[SynResult] End-to-end (keygen → CPA both fronts → MQ complete/verify), 40 independent
keys, suffix 300 sigs / prefix 100 sigs:

| sigma | exact full-vector recovery | false certifications |
|---:|---:|---:|
| 0.0 / 1.0 / 2.0 | **100%** | 0 |
| 4.0 | 2.5% (suffix under-resourced — see below) | 0 |

[SynResult] The `sigma = 4` dip is **not** an assembly failure: it is the suffix front
(Candidate C) needing more signatures as noise grows (a Part-1 property). Holding
`sigma = 4` and increasing the suffix signature budget:

| suffix signatures | full-vector recovery |
|---:|---:|
| 300 | 0% |
| 800 | 86.7% |
| 2000 / 4000 | **100%** |

The prefix front (Candidate B) is already noise-robust at `sigma = 4`; the bottleneck is
purely the suffix vertical-CPA sample size, exactly as Part 1 characterised.

## 5. The two ambiguities, resolved

[SynResult] **Global polarity.** Feeding the opposite global polarity (the complemented
suffix) to the completer: the MQ system selects the **`complemented` branch** and still
recovers `x` exactly. So whichever way the device's leakage sign resolves, one public MQ
check fixes it — at most 2 global candidates, never `2^32`.

[SynResult] **Zero-byte completion.** Forcing `x[5] = 0`: Candidate B flags coord 5 as
unknown (dead channel), and the MQ system completes it to its true value `0`, yielding full
recovery. Across the noise sweep, every occurring zero byte (2–5 per 40-key batch) was
completed with zero false certifications.

[SynResult] **Certification soundness (negative control).** Sabotaging one correctly
recovered suffix byte before verification: the MQ system certifies **nothing**
(0 candidates accepted). Certification is sound, not a rubber stamp.

## 6. Conclusion — objective achieved

[SynResult] Under the project's standing monotone-leakage assumption, the **two-front CPA
pipeline recovers the complete 48-byte MQOM v2.1 witness `x` exactly (`x_hat == x`)** in
simulation: suffix by Candidate C, prefix by Candidate B, with the public MQ system
resolving a single global polarity bit and completing the rare self-detected zero byte, and
certifying the result. Full recovery is 100% across keys once each CPA front is in its
working regime (a few hundred signatures at `sigma ≤ 2`; more on the suffix front at higher
noise). Because recovery is clean, the fallback top-3 high-potential-paths deliverable is
**not required**.

This is a demonstration under explicitly stated synthetic leakage models — a property of
the models and the MQOM structure, **not** a demonstrated vulnerability of any real MQOM
implementation or device. The conditions under which full recovery holds (monotone leakage;
per-front signature budgets; the `x_j = 0` completion; the global-polarity resolution) are
the scientific content.

## 7. Report mapping
- Ch3 (Proposed Work): §1–3 the assembly + MQ-completion design, integrity framing.
- Ch4 (Simulation & Results): §2 certifier sharpness, §4 recovery tables, §5 ambiguity resolution + controls.
- Ch5 (Conclusions): §6 full-vector recovery achieved; conditions and scope.
