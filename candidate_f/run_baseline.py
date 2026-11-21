"""
Candidate F baseline experiment -- PREFIX backup (second-order CPA).

Run: python candidate_f/run_baseline.py   ->  results_f_baseline.json
All synthetic; fixed seeds.

Shows (1) pooled-HW second-order recovers HW(delta) only (HW-class collapse), so F
alone cannot recover the prefix; (2) bit-level second-order recovers full delta,
delimiting F's envelope.  Positions F honestly as a partial backup to Candidate B.
"""
import json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from candidate_f.model_f import (
    LAMBDA_BYTES, gen_delta, tree_shares, leak_pooled_hw, leak_bitlevel,
    so_hw_estimate, so_bits_recover, hw_class_size,
)
from gf256 import HW

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_f_baseline.json")
SEED = 20261122


def experiment_pooled_hw(n_bytes=300, n_sig=40000, sigmas=(0.5, 1.0, 2.0)):
    """HW(delta) estimation accuracy + the HW-class identifiability ceiling."""
    rows = []
    for sigma in sigmas:
        rng = np.random.default_rng(SEED + 20)
        errs = []; hw_hit = 0
        for _ in range(n_bytes):
            d = int(rng.integers(0, 256))
            r, n3 = tree_shares(d, n_sig, rng)
            L2, L3 = leak_pooled_hw(r, n3, sigma, rng)
            cov, hw_est = so_hw_estimate(L2, L3)
            errs.append(hw_est - int(HW[d]))
            hw_hit += int(round(hw_est) == int(HW[d]))
        errs = np.array(errs)
        rows.append({
            "sigma": sigma, "n_sig": n_sig,
            "hw_estimate_bias": float(errs.mean()),
            "hw_estimate_std": float(errs.std()),
            "hw_class_exact_rate": hw_hit / n_bytes,
        })
    # Candidate-set reduction: average HW-class size over the byte distribution.
    avg_class = float(np.mean([hw_class_size(int(HW[v])) for v in range(256)]))
    return rows, avg_class


def experiment_bitlevel(n_bytes=200, n_sig=20000, sigmas=(0.25, 0.5, 1.0, 2.0)):
    """Full delta-byte recovery under the stronger per-bit leakage assumption."""
    rows = []
    for sigma in sigmas:
        rng = np.random.default_rng(SEED + 21)
        ok = 0; bit_err = 0
        for _ in range(n_bytes):
            d = int(rng.integers(0, 256))
            r, n3 = tree_shares(d, n_sig, rng)
            b2, b3 = leak_bitlevel(r, n3, sigma, rng)
            drec, _ = so_bits_recover(b2, b3)
            ok += int(drec == d); bit_err += bin(drec ^ d).count("1")
        rows.append({"sigma": sigma, "n_sig": n_sig,
                     "byte_exact_rate": ok / n_bytes,
                     "bit_error_rate": bit_err / (8 * n_bytes)})
    return rows


def experiment_traces_pooled(d_hw_target=None, sigma=1.0,
                             grid=(1000, 5000, 20000, 80000), n_bytes=100):
    """How many signatures the pooled-HW HW(delta) estimate needs to stabilise."""
    rng = np.random.default_rng(SEED + 22)
    rows = []
    for n_sig in grid:
        hit = 0
        for _ in range(n_bytes):
            d = int(rng.integers(0, 256))
            r, n3 = tree_shares(d, n_sig, rng)
            L2, L3 = leak_pooled_hw(r, n3, sigma, rng)
            _, hw_est = so_hw_estimate(L2, L3)
            hit += int(round(hw_est) == int(HW[d]))
        rows.append({"n_sig": n_sig, "sigma": sigma, "hw_class_exact_rate": hit / n_bytes})
    return rows


if __name__ == "__main__":
    print("=" * 76)
    print("CANDIDATE F -- second-order CPA on delta = FirstBits_128(x)  (PREFIX backup)")
    print("node2 = rseed (fresh mask), node3 = rseed XOR delta; rseed hidden, refreshed/sig")
    print("=" * 76)

    print("\n[1] Pooled-HW second-order: identifiable quantity = HW(delta)")
    pooled, avg_class = experiment_pooled_hw()
    print(f"    {'sigma':>6} {'HW bias':>9} {'HW std':>8} {'HW-class exact':>15}")
    for r in pooled:
        print(f"    {r['sigma']:>6.2f} {r['hw_estimate_bias']:>+9.3f} {r['hw_estimate_std']:>8.3f} "
              f"{r['hw_class_exact_rate']*100:>14.1f}%")
    print(f"    => recovers HW class only (Cov = 2 - HW(delta)/2). Avg candidates left")
    print(f"       per byte = {avg_class:.1f} of 256  => F ALONE cannot recover the prefix.")

    print("\n[2] Pooled-HW signatures-to-stabilise (sigma=1.0)")
    ttp = experiment_traces_pooled()
    print(f"    {'n_sig':>7} {'HW-class exact':>15}")
    for r in ttp:
        print(f"    {r['n_sig']:>7} {r['hw_class_exact_rate']*100:>14.1f}%")

    print("\n[3] Bit-level second-order (STRONGER assumption): full delta recoverable")
    bl = experiment_bitlevel()
    print(f"    {'sigma':>6} {'byte-exact':>11} {'bit-error':>10}")
    for r in bl:
        print(f"    {r['sigma']:>6.2f} {r['byte_exact_rate']*100:>10.1f}% {r['bit_error_rate']*100:>9.2f}%")

    with open(OUT, "w") as f:
        json.dump({"pooled_hw": pooled, "avg_hw_class_size": avg_class,
                   "pooled_traces": ttp, "bitlevel": bl}, f, indent=2)
    print(f"\nSaved -> {OUT}")
