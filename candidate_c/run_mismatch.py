"""
Candidate C -- model-mismatch / robustness study.

Question: the baseline recovered the suffix when the attacker's leakage model (HW)
matched the generator. Does recovery SURVIVE when the TRUE device leakage is NOT plain
Hamming weight, while the attacker still assumes HW?  We generate synthetic leakage of
the secret operand acc_x under several hypothetical leakage shapes and attack each with
the same signed HW-CPA. We also test a linear-regression (stochastic/LRA) distinguisher
and document a structural fact about it on bare-XOR targets.

All synthetic. No physical measurement. Reproducible (fixed seeds).
"""
import json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from candidate_c.model_c import (
    N_COORDS, SUFFIX, gen_secret, simulate_observations, cpa_byte, rank_of_true,
)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_c_mismatch.json")


# ----------------------------------------------------------------------------
# Hypothetical leakage shapes for the SECRET operand acc_x (the "true device").
# Each is a per-bit weight vector w (len 8); leakage = sum_k w_k * bit_k(acc_x) + noise.
# We standardise each clean leakage to the same std as HW (sqrt(2)) so the comparison
# isolates leakage SHAPE from magnitude; noise sigma is then comparable across models.
# ----------------------------------------------------------------------------
def make_weight_sets(seed=2026):
    rng = np.random.default_rng(seed)
    w = {
        "HW_uniform":        np.ones(8),
        "weighted_mild":     1.0 + 0.15 * rng.standard_normal(8),
        "weighted_strong":   1.0 + 0.50 * rng.standard_normal(8),
        "weighted_uniform":  rng.uniform(0.2, 1.8, 8),
        "dominant_bit":      np.array([0.3,0.3,0.3,3.0,0.3,0.3,0.3,0.3]),
        "nonmonotone_flip":  np.array([1.0,1.0,-1.0,1.0,1.0,1.0,1.0,1.0]),  # stress: one bit leaks "backwards"
    }
    return w


_BITW = np.array([128,64,32,16,8,4,2,1], dtype=np.uint8)
def _bits(vals):
    """(n,) uint8 -> (n,8) float bits, MSB first."""
    return ((vals[:, None] & _BITW[None, :]) > 0).astype(np.float64)


def leak_weighted(accx_col, w, sigma, rng):
    clean = _bits(accx_col) @ w
    clean = (clean - clean.mean())
    s = clean.std()
    if s > 0:
        clean = clean / s * np.sqrt(2.0)   # standardise to HW-like std
    return clean + rng.normal(0.0, sigma, size=clean.shape)


# ----------------------------------------------------------------------------
# Linear Regression Analysis (LRA) distinguisher with the linear 8-bit basis.
# For each guess g: fit L ~ [1, bits(g XOR d)], score by R^2, pick max.
# ----------------------------------------------------------------------------
_G = np.arange(256, dtype=np.uint8)

def lra_byte_r2(delta_col, leak_col):
    """Return R^2 for every key guess (256,). Used to demonstrate LRA degeneracy."""
    L = leak_col - leak_col.mean()
    sstot = (L**2).sum() + 1e-12
    r2 = np.empty(256)
    for g in range(256):
        acc_pred = (g ^ delta_col).astype(np.uint8)
        X = np.concatenate([np.ones((len(L),1)), _bits(acc_pred)], axis=1)  # (n,9)
        beta, *_ = np.linalg.lstsq(X, L, rcond=None)
        res = L - X @ beta
        r2[g] = 1.0 - (res**2).sum()/sstot
    return r2


# ----------------------------------------------------------------------------
# Experiments
# ----------------------------------------------------------------------------
def mismatch_table(n_sig=3000, sigmas=(1.0, 2.0), n_keys=20, seed=314):
    """Signed HW-CPA recovery of the 32-byte suffix under each true leakage shape."""
    weights = make_weight_sets()
    rng = np.random.default_rng(seed)
    rows = []
    for name, w in weights.items():
        for sigma in sigmas:
            full_ok, per_ok, tot, ranks = 0, 0, 0, []
            for _ in range(n_keys):
                x = gen_secret(rng)
                delta, accx = simulate_observations(x, n_sig, rng)
                xhat = x.copy(); ok_bytes = 0
                for k in SUFFIX:
                    leak = leak_weighted(accx[:, k], w, sigma, rng)
                    corr = cpa_byte(delta[:, k], leak, signed=True)   # attacker ASSUMES HW
                    r = rank_of_true(corr, int(x[k])); ranks.append(r)
                    xhat[k] = int(np.argmax(corr))
                    ok_bytes += int(r == 0)
                per_ok += ok_bytes; tot += len(SUFFIX)
                full_ok += int(np.array_equal(xhat[SUFFIX], x[SUFFIX]))
            rows.append({
                "true_leakage": name, "attack_model": "signed_HW_CPA", "sigma": sigma,
                "n_sig": n_sig, "full_suffix_recovery": full_ok/n_keys,
                "per_byte_recovery": per_ok/tot, "mean_rank": float(np.mean(ranks)),
            })
    return rows


def lra_degeneracy_check(n_sig=3000, sigma=1.0, seed=5):
    """
    Structural fact: for a bare-XOR (key-additive) target, the 8-bit linear basis
    span{1, bits(g XOR d)} = span{1, bits(d)} is INDEPENDENT of g. So LRA with the
    linear basis gives ~identical R^2 for every key guess -> ZERO distinguishing power.
    We confirm empirically: spread of R^2 across the 256 guesses should be ~0.
    """
    rng = np.random.default_rng(seed)
    x = gen_secret(rng)
    delta, accx = simulate_observations(x, n_sig, rng)
    k = int(SUFFIX[0])
    # Use a weighted (non-HW) true leakage so this is not trivially HW.
    w = make_weight_sets()["weighted_strong"]
    leak = leak_weighted(accx[:, k], w, sigma, rng)
    r2 = lra_byte_r2(delta[:, k], leak)
    return {
        "r2_mean": float(r2.mean()), "r2_std_across_guesses": float(r2.std()),
        "r2_max_minus_min": float(r2.max() - r2.min()),
        "true_key_rank_by_r2": rank_of_true(r2, int(x[k])),
        "note": "std ~ 0 confirms LRA(linear basis) cannot distinguish keys on a bare-XOR target",
    }


if __name__ == "__main__":
    print("=" * 78)
    print("CANDIDATE C -- MODEL-MISMATCH / ROBUSTNESS  (attacker always assumes plain HW)")
    print("=" * 78)

    print("\n[A] Signed HW-CPA full-suffix recovery vs TRUE leakage shape (20 keys, 3000 sig)")
    rows = mismatch_table()
    print(f"    {'true leakage':>18} {'sigma':>6} {'per-byte':>9} {'full-suffix':>12} {'mean rank':>10}")
    for r in rows:
        print(f"    {r['true_leakage']:>18} {r['sigma']:>6.1f} {r['per_byte_recovery']*100:>8.1f}% "
              f"{r['full_suffix_recovery']*100:>11.1f}% {r['mean_rank']:>10.2f}")

    print("\n[B] LRA (linear-basis regression) degeneracy on the bare-XOR target")
    lra = lra_degeneracy_check()
    print(f"    R^2 mean across 256 guesses = {lra['r2_mean']:.4f}, "
          f"std = {lra['r2_std_across_guesses']:.2e}, max-min = {lra['r2_max_minus_min']:.2e}")
    print(f"    true-key rank by R^2 = {lra['true_key_rank_by_r2']} (meaningless: all guesses tie) "
          f"-> {lra['note']}")

    with open(OUT, "w") as f:
        json.dump({"mismatch_table": rows, "lra_degeneracy": lra}, f, indent=2)
    print(f"\nSaved -> {OUT}")
