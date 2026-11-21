"""
Candidate B model-mismatch / robustness experiment -- PREFIX.

Attacker ALWAYS predicts plain HW.  True device leakage is generated under several
shapes.  We measure full-prefix recovery (over NON-ZERO bytes) and the correct-key
margin, and run the "more data -> wrong maximum" probe that the linear-GF-map
literature warns about (MAYO, MDPI Cryptography 2026; SDitH, ePrint 2024/1882).

Run: python candidate_b/run_mismatch.py   ->  results_b_mismatch.json
All synthetic; fixed seeds.
"""
import json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from candidate_b.model_b import (
    LAMBDA_BYTES, PREFIX, gen_secret, multiplier_stream, leak_products,
    cpa_coord, positions_for_coord, PHI_HW, PHI_WHW, PHI_NONMONO,
)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_b_mismatch.json")
SEED = 20261122

SHAPES = [
    ("matched_HW", PHI_HW),
    ("weighted_HW_monotone", PHI_WHW),
    ("non_monotone_stress", PHI_NONMONO),
]


def recover_prefix_nonzero(x, sigma, n_sig, rng, phi):
    """Recover prefix; return per-byte ok over NON-ZERO bytes and the margins."""
    ok = 0; tot = 0; margins = []
    for j in PREFIX:
        if int(x[j]) == 0:
            continue
        mult = multiplier_stream(j, rng)
        L = leak_products(int(x[j]), mult, sigma, n_sig, rng, phi=phi)  # generated under phi
        corr = cpa_coord(mult, L)                                       # attacker predicts HW
        guess = int(np.argmax(corr))
        bw = float(np.max(np.delete(corr, int(x[j]))))
        margins.append(float(corr[int(x[j])] - bw))
        ok += int(guess == int(x[j])); tot += 1
    return ok, tot, margins


def experiment_mismatch_sweep(n_keys=30, n_sig=100, sigmas=(0.0, 1.0, 2.0, 4.0, 8.0)):
    rows = []
    for name, phi in SHAPES:
        for sigma in sigmas:
            rng = np.random.default_rng(SEED + 11)
            ok = tot = 0; margs = []
            for _ in range(n_keys):
                x = gen_secret(rng)
                o, t, m = recover_prefix_nonzero(x, sigma, n_sig, rng, phi)
                ok += o; tot += t; margs.extend(m)
            rows.append({
                "gen_shape": name, "sigma": sigma, "n_sig": n_sig,
                "nonzero_byte_recovery_rate": ok / tot,
                "mean_margin": float(np.mean(margs)),
                "frac_negative_margin": float(np.mean(np.array(margs) < 0)),
            })
    return rows


def experiment_wrongmax_probe(coord=8, n_keys=300, n_sig_grid=(1, 10, 100, 1000)):
    """
    'More data -> wrong max' probe.  Noise fixed at sigma=2; we increase the number
    of averaged signatures (more effective data) and watch whether added data under a
    MISMATCHED model drives the estimate toward the correct byte or an alias.
    Pure HW / monotone should converge to the truth; non-monotone is where a linear
    alias can win.  (nonzero keys only.)
    """
    rows = []
    sigma = 2.0
    for name, phi in SHAPES:
        for n_sig in n_sig_grid:
            rng = np.random.default_rng(SEED + 12)
            ok = 0
            for _ in range(n_keys):
                xj = int(rng.integers(1, 256))
                mult = multiplier_stream(coord, rng)
                L = leak_products(xj, mult, sigma, n_sig, rng, phi=phi)
                ok += int(np.argmax(cpa_coord(mult, L)) == xj)
            rows.append({"gen_shape": name, "sigma": sigma, "n_sig": n_sig,
                         "per_byte_recovery_rate": ok / n_keys})
    return rows


def experiment_nonmono_boundary(coord=15, n_keys=300, sigma=4.0,
                                 pos_grid=(8, 16, 32, 64, 128, 256, 512)):
    """
    Where DOES the shrunken non-monotone margin finally fail?  Fix high per-position
    noise (single-trace, sigma=4) and starve the attacker of horizontal positions.
    Contrast matched-HW vs non-monotone: the ~4x smaller non-monotone margin needs
    ~order-of-magnitude more positions to reach the same reliability.
    """
    rows = []
    for name, phi in [("matched_HW", PHI_HW), ("non_monotone_stress", PHI_NONMONO)]:
        for P in pos_grid:
            rng = np.random.default_rng(SEED + 13)
            ok = 0
            for _ in range(n_keys):
                xj = int(rng.integers(1, 256))
                mult = multiplier_stream(coord, rng)[:P]
                L = leak_products(xj, mult, sigma, 1, rng, phi=phi)   # single trace
                ok += int(np.argmax(cpa_coord(mult, L)) == xj)
            rows.append({"gen_shape": name, "positions": P, "sigma": sigma,
                         "n_sig": 1, "per_byte_recovery_rate": ok / n_keys})
    return rows


if __name__ == "__main__":
    print("=" * 76)
    print("CANDIDATE B -- model-mismatch robustness (attacker always predicts plain HW)")
    print("PREFIX; recovery measured over NON-ZERO bytes (x_j=0 is a separate structural case)")
    print("=" * 76)

    print("\n[1] Mismatch noise sweep -- full nonzero-prefix recovery, 30 keys, 100 sigs")
    sweep = experiment_mismatch_sweep()
    print(f"    {'gen shape':>22} {'sigma':>6} {'nonzero rec':>12} {'mean margin':>12} {'neg-margin%':>11}")
    for r in sweep:
        print(f"    {r['gen_shape']:>22} {r['sigma']:>6.1f} {r['nonzero_byte_recovery_rate']*100:>11.1f}% "
              f"{r['mean_margin']:>12.3f} {r['frac_negative_margin']*100:>10.1f}%")

    print("\n[2] 'More data -> wrong max' probe (sigma=2, increasing averaged sigs)")
    probe = experiment_wrongmax_probe()
    print(f"    {'gen shape':>22} {'n_sig':>6} {'per-byte rec':>13}")
    for r in probe:
        print(f"    {r['gen_shape']:>22} {r['n_sig']:>6} {r['per_byte_recovery_rate']*100:>12.1f}%")

    print("\n[3] Non-monotone failure boundary -- single trace, sigma=4, starved positions")
    bnd = experiment_nonmono_boundary()
    print(f"    {'gen shape':>22} {'positions':>9} {'per-byte rec':>13}")
    for r in bnd:
        print(f"    {r['gen_shape']:>22} {r['positions']:>9} {r['per_byte_recovery_rate']*100:>12.1f}%")

    with open(OUT, "w") as f:
        json.dump({"mismatch_sweep": sweep, "wrongmax_probe": probe,
                   "nonmono_boundary": bnd}, f, indent=2)
    print(f"\nSaved -> {OUT}")
