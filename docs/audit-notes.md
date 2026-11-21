# Independent Audit — notes

An independent, skeptical audit was run over the whole repository (field math, all three
parts, and the assembly/verification) to check correctness and research integrity. The
auditor re-ran the entire suite from scratch and re-derived every load-bearing claim with
its own code.

## Verdict: SOUND (high confidence)

The core claim — a two-front CPA pipeline recovers the full 48-byte witness `x` exactly
(`x_hat == x`), honestly, as a synthetic-model demonstration — is well supported.

- **No success-by-construction and no secret leakage.** Distinguishers consume only public
  data + synthetic leakage; the secret is used only by the leakage generators and
  ground-truth scoring. Decisive cross-check: CPA **alone** (MQ step disabled) already
  recovers 48/48 bytes on 40/40 keys at σ=2, so the algebra is not doing the recovery.
- **Math verified independently:** GF(256) `mul` checked on all 65,536 pairs (0
  mismatches); CPA Pearson matches `numpy` to <1e-9; `mq_eval` matches a naive reference;
  the Candidate F identity `Cov(HW(r),HW(r⊕δ)) = 2 − HW(δ)/2` and the HW-class ceiling
  (50.27) are exact; LRA degeneracy on the bare-XOR target confirmed.
- **All tables reproduce**; integrity rules (synthetic-only, monotone-primary,
  algebra-only-verifies) hold throughout; negative controls are meaningful and pass.

## Minor findings (all addressed)

1. "one wrong byte → 0/48" was slightly overstated (empirically ≤3/48 by chance, never
   48/48). Reworded to "≈0/48" in `docs/part3_assembly.md` and `RESEARCH_LOG.md`.
2. `xhat = x.copy()` code smell in the two Part-1 runners (harmless — all scored suffix
   bytes are overwritten via argmax — but reads like leakage). Changed to zero-init.
3. "19 positions suffice" clarified as conditional on ~100 averaged signatures (single-trace
   needs ~256–512 positions); suffix "unconditional" clarified as under monotone leakage.

None of these affect the result. Cosmetic bookkeeping note: `zero_bytes_completed_total`
counts flagged unknowns on certified keys (equals total completed since unknown=0 otherwise).

## Scope reminder
All results are synthetic demonstrations under explicitly stated leakage models — a property
of the models and the MQOM structure, not a demonstrated vulnerability of any real device.
