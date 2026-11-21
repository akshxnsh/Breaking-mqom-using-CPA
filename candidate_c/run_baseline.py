"""
Candidate C baseline experiment (matched HW leakage model).

Run: python candidate_c/run_baseline.py
All randomness is seeded -> fully reproducible. Results also written to results_c_baseline.json.

SCIENTIFIC STATUS: every number below is a SYNTHETIC result under an explicitly
stated leakage hypothesis. It demonstrates recovery *under that model*, not a
physical vulnerability of MQOM.
"""
import json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from candidate_c.model_c import (
    N_COORDS, LAMBDA_BYTES, SUFFIX, gen_secret, simulate_observations,
    leak_hw, cpa_byte, rank_of_true,
)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_c_baseline.json")


def recover_suffix(x, delta, accx, sigma, rng):
    """Attack every suffix byte; return per-byte rank array and recovered vector."""
    ranks = np.full(N_COORDS, -1, dtype=int)
    xhat = np.zeros(N_COORDS, dtype=np.uint8)   # built purely from argmax (no secret seeding)
    for k in SUFFIX:
        leak = leak_hw(accx[:, k], sigma, rng)
        corr = cpa_byte(delta[:, k], leak)
        ranks[k] = rank_of_true(corr, int(x[k]))
        xhat[k] = int(np.argmax(corr))
    return ranks, xhat


def experiment_noise_sweep(n_sig=4000, sigmas=(0.0, 0.5, 1.0, 2.0, 4.0), n_keys=30, seed=20261122):
    """Full-suffix recovery rate vs noise, averaged over independent keys."""
    rng = np.random.default_rng(seed)
    rows = []
    for sigma in sigmas:
        full_ok = 0
        per_byte_ok = 0
        total_bytes = 0
        rank_accum = []
        for _ in range(n_keys):
            x = gen_secret(rng)
            delta, accx = simulate_observations(x, n_sig, rng)
            ranks, xhat = recover_suffix(x, delta, accx, sigma, rng)
            suffix_ranks = ranks[SUFFIX]
            per_byte_ok += int((suffix_ranks == 0).sum())
            total_bytes += len(SUFFIX)
            rank_accum.extend(suffix_ranks.tolist())
            full_ok += int(np.array_equal(xhat[SUFFIX], x[SUFFIX]))
        rows.append({
            "sigma": sigma,
            "n_sig": n_sig,
            "full_suffix_recovery_rate": full_ok / n_keys,
            "per_byte_recovery_rate": per_byte_ok / total_bytes,
            "mean_rank": float(np.mean(rank_accum)),
            "median_rank": float(np.median(rank_accum)),
        })
    return rows


def experiment_traces_to_disclosure(sigma=2.0, grid=(50, 100, 200, 400, 800, 1600, 3200), n_keys=20, seed=7):
    """Per-byte top-1 recovery rate vs number of signatures, at a fixed noise level."""
    rng = np.random.default_rng(seed)
    rows = []
    for n_sig in grid:
        ok, tot = 0, 0
        for _ in range(n_keys):
            x = gen_secret(rng)
            delta, accx = simulate_observations(x, n_sig, rng)
            ranks, _ = recover_suffix(x, delta, accx, sigma, rng)
            ok += int((ranks[SUFFIX] == 0).sum())
            tot += len(SUFFIX)
        rows.append({"n_sig": n_sig, "sigma": sigma, "per_byte_recovery_rate": ok / tot})
    return rows


def demonstrate_complement_ambiguity(n_sig=4000, sigma=1.0, seed=1):
    """
    Show the irreducible {x, x XOR 0xFF} ambiguity of |corr| on a bare-XOR target,
    and that the SIGNED correlation (assumed positive-HW polarity) resolves it.
    """
    rng = np.random.default_rng(seed)
    x = gen_secret(rng)
    delta, accx = simulate_observations(x, n_sig, rng)
    k = int(SUFFIX[0]); true = int(x[k]); comp = true ^ 0xFF
    leak = leak_hw(accx[:, k], sigma, rng)

    c_abs = cpa_byte(delta[:, k], leak, signed=False)
    c_sig = cpa_byte(delta[:, k], leak, signed=True)
    order_abs = np.argsort(-c_abs)
    return {
        "true_key": true, "complement_key": comp,
        "abs_rank_true": int(np.where(order_abs == true)[0][0]),
        "abs_top2_keys": [int(order_abs[0]), int(order_abs[1])],
        "abs_corr_true": float(c_abs[true]), "abs_corr_complement": float(c_abs[comp]),
        "signed_rank_true": rank_of_true(c_sig, true),
        "signed_corr_true": float(c_sig[true]), "signed_corr_complement": float(c_sig[comp]),
    }


def negative_controls(n_sig=4000, sigma=2.0, seed=99):
    """
    (1) Prefix control: attack a prefix coord (Delta_x = 0, constant) -> no varying data.
        CPA must NOT single out the true key (true-key rank should look random ~ uniform).
    (2) Shuffled-leakage control: break the leak<->delta pairing -> correlation collapses.
    """
    rng = np.random.default_rng(seed)
    x = gen_secret(rng)
    delta, accx = simulate_observations(x, n_sig, rng)

    # (1) Prefix coordinate k = 0: delta is all-zero, acc_x[0] = x[0] constant.
    leak0 = leak_hw(accx[:, 0], sigma, rng)
    corr0 = cpa_byte(delta[:, 0], leak0)
    prefix_rank = rank_of_true(corr0, int(x[0]))

    # (2) A valid suffix coord, but shuffle the leakage against delta.
    k = int(SUFFIX[0])
    leak = leak_hw(accx[:, k], sigma, rng)
    perm = rng.permutation(n_sig)
    corr_shuf = cpa_byte(delta[:, k], leak[perm])
    shuf_rank = rank_of_true(corr_shuf, int(x[k]))
    shuf_margin = float(np.sort(corr_shuf)[-1] - np.sort(corr_shuf)[-2])

    # For contrast: the same suffix coord attacked correctly.
    corr_ok = cpa_byte(delta[:, k], leak)
    ok_rank = rank_of_true(corr_ok, int(x[k]))
    ok_true_corr = float(corr_ok[int(x[k])])
    ok_best_wrong = float(np.max(np.delete(corr_ok, int(x[k]))))

    return {
        "prefix_constant_data_rank": prefix_rank,        # expect NOT 0 (no handle)
        "shuffled_leakage_rank": shuf_rank,              # expect ~random, not 0
        "shuffled_top_margin": shuf_margin,             # expect ~0
        "matched_suffix_rank": ok_rank,                 # expect 0
        "matched_true_corr": ok_true_corr,
        "matched_best_wrong_corr": ok_best_wrong,
        "matched_margin": ok_true_corr - ok_best_wrong,
    }


if __name__ == "__main__":
    print("=" * 74)
    print("CANDIDATE C  --  vertical key-XOR CPA  (SYNTHETIC leakage: L = HW(acc_x)+noise)")
    print("gf256-short L1: n=48, suffix coords k=16..47 (32 bytes attackable)")
    print("=" * 74)

    print("\n[0] Complement-ambiguity diagnostic (why |corr| fails, signed corr fixes it)")
    amb = demonstrate_complement_ambiguity()
    print(f"    true key = {amb['true_key']:#04x}, complement = {amb['complement_key']:#04x}")
    print(f"    |corr|  : true rank = {amb['abs_rank_true']}, top-2 keys = "
          f"[{amb['abs_top2_keys'][0]:#04x}, {amb['abs_top2_keys'][1]:#04x}]  "
          f"(|corr| true={amb['abs_corr_true']:.4f}, complement={amb['abs_corr_complement']:.4f}  -> TIED)")
    print(f"    signed  : true rank = {amb['signed_rank_true']}  "
          f"(signed true={amb['signed_corr_true']:+.4f}, complement={amb['signed_corr_complement']:+.4f}  -> SEPARATED)")

    print("\n[1] Noise sweep -- full 32-byte suffix recovery (SIGNED CPA), 30 keys, 4000 sigs")
    sweep = experiment_noise_sweep()
    print(f"    {'sigma':>6} {'per-byte rec':>13} {'full-suffix rec':>16} {'mean rank':>10} {'median rank':>12}")
    for r in sweep:
        print(f"    {r['sigma']:>6.1f} {r['per_byte_recovery_rate']*100:>12.1f}% "
              f"{r['full_suffix_recovery_rate']*100:>15.1f}% {r['mean_rank']:>10.2f} {r['median_rank']:>12.1f}")

    print("\n[2] Traces-to-disclosure -- per-byte top-1 rate vs #signatures (sigma=2.0, 20 keys)")
    ttd = experiment_traces_to_disclosure()
    print(f"    {'#sig':>6} {'per-byte rec':>13}")
    for r in ttd:
        print(f"    {r['n_sig']:>6} {r['per_byte_recovery_rate']*100:>12.1f}%")

    print("\n[3] Negative controls (sigma=2.0, 4000 sigs)")
    nc = negative_controls()
    print(f"    prefix coord (Delta_x=0, no varying data): true-key rank = {nc['prefix_constant_data_rank']:>3}  (expect NOT 0 / ~random)")
    print(f"    shuffled leakage vs delta:                 true-key rank = {nc['shuffled_leakage_rank']:>3}  (expect ~random), top margin = {nc['shuffled_top_margin']:.4f}")
    print(f"    matched suffix coord (control contrast):   true-key rank = {nc['matched_suffix_rank']:>3}  (expect 0)")
    print(f"       correct-key corr = {nc['matched_true_corr']:.4f} | best wrong = {nc['matched_best_wrong_corr']:.4f} | margin = {nc['matched_margin']:.4f}")

    with open(OUT, "w") as f:
        json.dump({"noise_sweep": sweep, "traces_to_disclosure": ttd, "negative_controls": nc}, f, indent=2)
    print(f"\nSaved -> {OUT}")
