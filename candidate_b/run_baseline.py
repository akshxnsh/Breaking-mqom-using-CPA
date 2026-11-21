"""
Candidate B baseline experiment (matched HW leakage model) -- PREFIX recovery.

Run: python candidate_b/run_baseline.py
All randomness is seeded -> fully reproducible. Results -> results_b_baseline.json.

SCIENTIFIC STATUS: every number below is a SYNTHETIC result under an explicitly
stated leakage hypothesis. It demonstrates recovery *under that model*, not a
physical vulnerability of MQOM.
"""
import json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from candidate_b.model_b import (
    N_COORDS, LAMBDA_BYTES, PREFIX, gen_secret, positions_for_coord,
    multiplier_stream, leak_products, cpa_coord, rank_of_true,
    alias_profile_noiseless, HWPRED,
)
from gf256 import mul, HW

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_b_baseline.json")
SEED = 20261122
ZERO_FLAG_THRESH = 0.30     # max|rho| below this => coordinate flagged as a dead/zero channel


def recover_prefix(x, sigma, n_sig, rng):
    """Attack every prefix byte; return per-byte rank, recovered vector, and max|rho|."""
    ranks = np.full(LAMBDA_BYTES, -1, dtype=int)
    xhat = np.zeros(LAMBDA_BYTES, dtype=np.uint8)
    maxrho = np.zeros(LAMBDA_BYTES)
    for j in PREFIX:
        mult = multiplier_stream(j, rng)
        L = leak_products(int(x[j]), mult, sigma, n_sig, rng)
        corr = cpa_coord(mult, L)
        ranks[j] = rank_of_true(corr, int(x[j]))
        xhat[j] = int(np.argmax(corr))
        maxrho[j] = float(corr.max())
    return ranks, xhat, maxrho


def experiment_noise_sweep(n_sig=100, sigmas=(0.0, 0.5, 1.0, 2.0, 4.0, 8.0), n_keys=40, seed=SEED):
    """
    Full-prefix recovery vs noise.  We report BOTH the raw full-16-byte rate and the
    rate over NON-ZERO bytes, because x_j = 0 is a structural multiplicative blind
    spot (x_j*a = 0 for all a -> dead channel), not a noise effect.
    """
    rng = np.random.default_rng(seed)
    rows = []
    for sigma in sigmas:
        full_ok = 0
        per_byte_ok = 0; total_bytes = 0
        nz_ok = 0; nz_total = 0
        zero_detected = 0; zero_total = 0
        rank_accum = []
        for _ in range(n_keys):
            x = gen_secret(rng)
            ranks, xhat, maxrho = recover_prefix(x, sigma, n_sig, rng)
            is_zero = (x[:LAMBDA_BYTES] == 0)
            per_byte_ok += int((ranks == 0).sum()); total_bytes += LAMBDA_BYTES
            nz = ~is_zero
            nz_ok += int((ranks[nz] == 0).sum()); nz_total += int(nz.sum())
            # zero bytes should be self-flagged by a collapsed max|rho|
            zero_total += int(is_zero.sum())
            zero_detected += int((maxrho[is_zero] < ZERO_FLAG_THRESH).sum())
            rank_accum.extend(ranks.tolist())
            full_ok += int(np.array_equal(xhat, x[:LAMBDA_BYTES]))
        rows.append({
            "sigma": sigma, "n_sig": n_sig,
            "full_prefix_recovery_rate": full_ok / n_keys,
            "per_byte_recovery_rate": per_byte_ok / total_bytes,
            "nonzero_byte_recovery_rate": (nz_ok / nz_total) if nz_total else None,
            "zero_byte_detection_rate": (zero_detected / zero_total) if zero_total else None,
            "zero_bytes_seen": zero_total,
            "mean_rank": float(np.mean(rank_accum)),
        })
    return rows


def experiment_positions_to_disclosure(sigma=2.0, n_sig=100, coord=8,
                                       fracs=(0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0),
                                       n_keys=60, seed=SEED + 2):
    """Per-byte top-1 recovery vs number of horizontal positions used (nonzero keys)."""
    rng = np.random.default_rng(seed)
    Pfull = positions_for_coord(coord)
    rows = []
    for fr in fracs:
        P = max(4, int(Pfull * fr))
        ok, tot = 0, 0
        for _ in range(n_keys):
            xj = int(rng.integers(1, 256))        # nonzero (zero handled separately)
            mult = multiplier_stream(coord, rng)[:P]
            L = leak_products(xj, mult, sigma, n_sig, rng)
            corr = cpa_coord(mult, L)
            ok += int(np.argmax(corr) == xj); tot += 1
        rows.append({"positions": P, "frac_of_full": fr, "sigma": sigma,
                     "per_byte_recovery_rate": ok / tot})
    return rows


def experiment_alias_structure(coord=8, keys=(0x11, 0x8D, 0xF2, 0x2A), seed=SEED + 5):
    """
    [Deduction+SynResult] Confirm wrong-key correlation depends only on c = g*x^-1,
    and report the noiseless margin ceiling (correct minus best alias).
    """
    rng = np.random.default_rng(seed)
    from gf256 import mul as gmul
    # inverse table
    inv = np.zeros(256, dtype=np.uint8)
    for a in range(1, 256):
        for b in range(1, 256):
            if int(gmul(np.uint8(a), np.uint8(b))) == 1:
                inv[a] = b; break
    profiles = []
    for x in keys:
        mult = multiplier_stream(coord, rng)
        rho = alias_profile_noiseless(x, mult)                 # |rho|(g)
        rho_by_c = np.zeros(256)
        for c in range(256):
            g = int(gmul(np.uint8(c), np.uint8(x)))
            rho_by_c[c] = rho[g]
        profiles.append(rho_by_c)
    P = np.array(profiles)
    max_std_over_c = float(np.max(np.std(P[:, 1:], axis=0)))    # c!=0
    rho_by_c = P[0]
    worst = [int(w) for w in np.argsort(-rho_by_c) if w != 1][:3]
    return {
        "coord": coord, "keys_tested": [int(k) for k in keys],
        "c_only_dependence_max_std": max_std_over_c,       # ->0 confirms c-only
        "correct_c1_rho": float(rho_by_c[1]),
        "top_aliases": [{"c": w, "rho": float(rho_by_c[w])} for w in worst],
        "noiseless_margin_ceiling": float(rho_by_c[1] - rho_by_c[worst[0]]),
    }


def experiment_zero_byte(sigma=1.0, n_sig=100, coord=8, n_trials=40, seed=SEED + 6):
    """
    The x_j = 0 structural blind spot, and its SELF-DETECTION via collapsed max|rho|.
    Also the mirror negative control: all-multiplier-zero positions carry nothing.
    """
    rng = np.random.default_rng(seed)
    zero_max, nz_max = [], []
    for _ in range(n_trials):
        mult = multiplier_stream(coord, rng)
        Lz = leak_products(0, mult, sigma, n_sig, rng)
        zero_max.append(float(cpa_coord(mult, Lz).max()))
        xj = int(rng.integers(1, 256))
        Ln = leak_products(xj, mult, sigma, n_sig, rng)
        nz_max.append(float(cpa_coord(mult, Ln).max()))
    return {
        "zero_byte_mean_max_rho": float(np.mean(zero_max)),
        "zero_byte_p95_max_rho": float(np.percentile(zero_max, 95)),
        "nonzero_byte_mean_max_rho": float(np.mean(nz_max)),
        "nonzero_byte_min_max_rho": float(np.min(nz_max)),
        "flag_threshold": ZERO_FLAG_THRESH,
        "separation_clean": bool(np.percentile(zero_max, 95) < ZERO_FLAG_THRESH <= np.min(nz_max)),
    }


def negative_controls(sigma=1.0, n_sig=100, coord=8, n_keys=50, seed=SEED + 7):
    """(1) all-multiplier-zero dead channel; (2) shuffled label null; (3) matched contrast."""
    rng = np.random.default_rng(seed)
    # (1) all multipliers zero -> all products 0 -> no information
    ok_zero = 0
    for _ in range(n_keys):
        xj = int(rng.integers(1, 256))
        mult = np.zeros(positions_for_coord(coord), dtype=np.uint8)
        L = leak_products(xj, mult, sigma, n_sig, rng)
        ok_zero += int(np.argmax(cpa_coord(mult, L)) == xj)
    # (2) shuffled label null
    ok_shuf = 0; shuf_margin = []
    for _ in range(n_keys):
        xj = int(rng.integers(1, 256))
        mult = multiplier_stream(coord, rng)
        L = leak_products(xj, mult, sigma, n_sig, rng)
        corr = cpa_coord(mult, L[rng.permutation(len(L))])
        s = np.sort(corr)
        shuf_margin.append(float(s[-1] - s[-2]))
        ok_shuf += int(np.argmax(corr) == xj)
    # (3) matched contrast
    xj = int(rng.integers(1, 256))
    mult = multiplier_stream(coord, rng)
    corr = cpa_coord(mult, leak_products(xj, mult, sigma, n_sig, rng))
    bw = float(np.max(np.delete(corr, xj)))
    return {
        "all_mult_zero_recovery_rate": ok_zero / n_keys,     # expect ~chance
        "shuffled_recovery_rate": ok_shuf / n_keys,          # expect ~chance
        "shuffled_mean_top_margin": float(np.mean(shuf_margin)),  # expect ~0
        "matched_true_rho": float(corr[xj]),
        "matched_best_wrong_rho": bw,
        "matched_margin": float(corr[xj] - bw),
    }


if __name__ == "__main__":
    print("=" * 76)
    print("CANDIDATE B -- horizontal CPA (SYNTHETIC leakage: L = HW(x_j * a) + noise)")
    print("gf256-short L1: n=48; PREFIX coords j=0..15 (16 bytes). Positions/coord ~1584-2304.")
    print("=" * 76)

    print("\n[1] Noise sweep -- full 16-byte prefix recovery, 40 keys, 100 sigs averaged")
    sweep = experiment_noise_sweep()
    print(f"    {'sigma':>6} {'per-byte':>9} {'NONZERO-byte':>13} {'full-prefix':>12} "
          f"{'0-byte detect':>14} {'mean rank':>10}")
    for r in sweep:
        zd = "n/a" if r['zero_byte_detection_rate'] is None else f"{r['zero_byte_detection_rate']*100:.0f}%"
        print(f"    {r['sigma']:>6.1f} {r['per_byte_recovery_rate']*100:>8.1f}% "
              f"{r['nonzero_byte_recovery_rate']*100:>12.1f}% {r['full_prefix_recovery_rate']*100:>11.1f}% "
              f"{zd:>14} {r['mean_rank']:>10.2f}")

    print("\n[2] Positions-to-disclosure -- per-byte top-1 vs #positions (coord 8, sigma=2, 60 keys)")
    ttd = experiment_positions_to_disclosure()
    print(f"    {'positions':>9} {'per-byte rec':>13}")
    for r in ttd:
        print(f"    {r['positions']:>9} {r['per_byte_recovery_rate']*100:>12.1f}%")

    print("\n[3] Aliasing structure -- wrong-key corr depends only on c = g * x^-1")
    al = experiment_alias_structure()
    print(f"    c-only dependence (max std of |rho|(c) across keys, c!=0): {al['c_only_dependence_max_std']:.2e}")
    print(f"    correct key c=1: |rho| = {al['correct_c1_rho']:.3f}")
    print(f"    top aliases: " + ", ".join(f"(c={a['c']:#04x}, |rho|={a['rho']:.3f})" for a in al['top_aliases']))
    print(f"    noiseless margin ceiling = {al['noiseless_margin_ceiling']:.3f}")

    print("\n[4] x_j = 0 structural blind spot + self-detection")
    zb = experiment_zero_byte()
    print(f"    zero byte   : mean max|rho| = {zb['zero_byte_mean_max_rho']:.3f}  (p95 = {zb['zero_byte_p95_max_rho']:.3f})")
    print(f"    nonzero byte: mean max|rho| = {zb['nonzero_byte_mean_max_rho']:.3f}  (min = {zb['nonzero_byte_min_max_rho']:.3f})")
    print(f"    clean separation at threshold {zb['flag_threshold']}: {zb['separation_clean']}  "
          f"=> a zero byte is DETECTED (then completed by the MQ system in Part 3)")

    print("\n[5] Negative controls (sigma=1.0, 100 sigs)")
    nc = negative_controls()
    print(f"    all-multiplier-zero channel: recovery = {nc['all_mult_zero_recovery_rate']*100:.1f}% (expect ~chance)")
    print(f"    shuffled-label null        : recovery = {nc['shuffled_recovery_rate']*100:.1f}% (expect ~chance), "
          f"mean top margin = {nc['shuffled_mean_top_margin']:.4f}")
    print(f"    matched contrast           : true {nc['matched_true_rho']:.3f} vs best-wrong "
          f"{nc['matched_best_wrong_rho']:.3f} (margin {nc['matched_margin']:.3f})")

    with open(OUT, "w") as f:
        json.dump({"noise_sweep": sweep, "positions_to_disclosure": ttd,
                   "alias_structure": al, "zero_byte": zb, "negative_controls": nc}, f, indent=2)
    print(f"\nSaved -> {OUT}")
