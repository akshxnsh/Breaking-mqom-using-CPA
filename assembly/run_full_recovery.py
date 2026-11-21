"""
Part 3 -- full-vector recovery: assemble CPA parts, let the public MQ system resolve
the residual ambiguities, and certify x_hat == x.

Run: python assembly/run_full_recovery.py   ->  results_full_recovery.json
All synthetic; fixed seeds.

PIPELINE
  1. keygen -> secret x, public (A, b, y).
  2. CPA (Parts 1-2) -> suffix sigma_hat (+ 1 global polarity bit), prefix pre_hat
     (+ self-detected x_j=0 coords left UNKNOWN).
  3. ALGEBRA = COMBINE/VERIFY/COMPLETE ONLY: brute the 2 polarities x the (rare)
     unknown bytes over GF(256), keep the unique assignment that satisfies all m
     equations.  This fixes the global sign and fills zero bytes; CPA did the 48-byte
     recovery.  Certification = the public MQ relation holds.

INTEGRITY: the MQ system NEVER substitutes for CPA.  It only disambiguates a single
global bit and completes <= a couple of bytes CPA itself flagged as unrecoverable.
"""
import json, os, sys, itertools, time
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from assembly.mq_system import gen_public_system, mq_eval, mq_eval_batch, verify, N, M
from assembly.assemble import assemble
from candidate_c.model_c import LAMBDA_BYTES, SUFFIX

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_full_recovery.json")
SEED = 20261122
UNKNOWN_CAP = 2     # brute at most this many self-detected zero bytes (more is astronomically rare)


def build_candidates(pre_hat, unknown, sig_hat):
    """All completion candidates: {2 polarities} x {256^|unknown| zero-byte fills}."""
    idx = np.where(unknown)[0]
    k = len(idx)
    if k > UNKNOWN_CAP:
        return None, idx
    if k == 0:
        fills = np.zeros((1, 0), dtype=np.uint8)
    else:
        fills = np.array(list(itertools.product(range(256), repeat=k)), dtype=np.uint8)
    blocks = []
    for suf in (sig_hat, np.bitwise_xor(sig_hat, np.uint8(0xFF))):
        base = np.concatenate([pre_hat, suf]).astype(np.uint8)          # (48,)
        block = np.tile(base, (fills.shape[0], 1))
        if k > 0:
            block[:, idx] = fills
        blocks.append(block)
    return np.vstack(blocks), idx


def complete_and_verify(A, b, y, pre_hat, unknown, sig_hat):
    """
    Return (x_hat or None, info).  Keeps the UNIQUE candidate that satisfies all m
    MQ equations.  info records polarity used, #zero bytes completed, #accepted.
    """
    cands, idx = build_candidates(pre_hat, unknown, sig_hat)
    if cands is None:
        return None, {"completion_limited": True, "n_unknown": int(len(idx))}
    Y = mq_eval_batch(A, b, cands)
    match = np.all(Y == y[None, :], axis=1)
    n_accept = int(match.sum())
    if n_accept == 0:
        return None, {"accepted": 0, "n_unknown": int(len(idx))}
    xhat = cands[np.argmax(match)]
    npol = cands.shape[0] // 2
    polarity = "direct" if np.argmax(match) < npol else "complemented"
    return xhat, {"accepted": n_accept, "n_unknown": int(len(idx)), "polarity": polarity}


# ---------------------------------------------------------------------------
def experiment_full_recovery(n_keys=60, sigma=2.0, n_sig_suffix=300, n_sig_prefix=100,
                             seed=SEED):
    """End-to-end exact full-vector recovery rate at a representative noise level."""
    rng = np.random.default_rng(seed)
    full_ok = 0
    polarity_complemented = 0
    zero_completed = 0
    false_accepts = 0
    unknown_hist = {}
    for _ in range(n_keys):
        x = rng.integers(0, 256, N, dtype=np.uint8)
        A, b = gen_public_system(rng)
        y = mq_eval(A, b, x)
        pre_hat, unknown, sig_hat = assemble(x, sigma, n_sig_suffix, sigma, n_sig_prefix, rng)
        xhat, info = complete_and_verify(A, b, y, pre_hat, unknown, sig_hat)
        unknown_hist[int(unknown.sum())] = unknown_hist.get(int(unknown.sum()), 0) + 1
        if xhat is not None:
            # A certified x_hat MUST equal the true secret (no false certification).
            if np.array_equal(xhat, x):
                full_ok += 1
            else:
                false_accepts += 1          # certified but wrong -> would be a real problem
            if info.get("polarity") == "complemented":
                polarity_complemented += 1
            zero_completed += info.get("n_unknown", 0)
    return {
        "sigma": sigma, "n_keys": n_keys,
        "n_sig_suffix": n_sig_suffix, "n_sig_prefix": n_sig_prefix,
        "full_vector_recovery_rate": full_ok / n_keys,
        "keys_needing_polarity_flip": polarity_complemented,
        "zero_bytes_completed_total": zero_completed,
        "false_certifications": false_accepts,
        "unknown_count_histogram": unknown_hist,
    }


def experiment_noise_sweep(sigmas=(0.0, 1.0, 2.0, 4.0), n_keys=40):
    rng_seed = SEED + 1
    rows = []
    for sigma in sigmas:
        rows.append(experiment_full_recovery(n_keys=n_keys, sigma=sigma, seed=rng_seed))
        rng_seed += 1
    return rows


def experiment_suffix_budget(sigma=4.0, grid=(300, 800, 2000, 4000), n_keys=30, seed=SEED + 5):
    """
    At high noise the full-vector rate is bottlenecked by the SUFFIX front (Candidate C),
    which needs more signatures as sigma grows (a Part-1 property) -- NOT by assembly.
    Show full recovery climbs back to 100% as the suffix signature budget increases.
    """
    rows = []
    for n_sig_suffix in grid:
        rows.append({**experiment_full_recovery(n_keys=n_keys, sigma=sigma,
                     n_sig_suffix=n_sig_suffix, n_sig_prefix=100, seed=seed),
                     "n_sig_suffix": n_sig_suffix})
    return rows


def experiment_polarity_resolution(seed=SEED + 11):
    """
    Explicitly exercise the global-polarity resolution the MQ system provides.
    If the device's leakage polarity had resolved the OTHER way, signed CPA would
    return the complemented suffix (sigma_hat XOR 0xFF). We simulate that and confirm
    the MQ step selects the 'complemented' candidate and still recovers x exactly.
    """
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, N, dtype=np.uint8)
    A, b = gen_public_system(rng)
    y = mq_eval(A, b, x)
    pre_hat, unknown, sig_hat = assemble(x, 2.0, 300, 2.0, 100, rng)
    sig_flipped = np.bitwise_xor(sig_hat, np.uint8(0xFF))   # opposite global polarity
    xhat, info = complete_and_verify(A, b, y, pre_hat, unknown, sig_flipped)
    return {
        "fed_complemented_suffix": True,
        "mq_selected_polarity": info.get("polarity"),       # expect 'complemented'
        "recovered_full_vector": bool(xhat is not None and np.array_equal(xhat, x)),
    }


def experiment_forced_zero(seed=SEED + 7):
    """Force a prefix byte to 0 and show the MQ system completes it to the true value."""
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, N, dtype=np.uint8)
    x[5] = 0                                   # guaranteed dead channel at coord 5
    A, b = gen_public_system(rng)
    y = mq_eval(A, b, x)
    pre_hat, unknown, sig_hat = assemble(x, 2.0, 300, 2.0, 100, rng)
    xhat, info = complete_and_verify(A, b, y, pre_hat, unknown, sig_hat)
    return {
        "forced_zero_coord": 5,
        "coord5_flagged_unknown": bool(unknown[5]),
        "completed_value_coord5": int(xhat[5]) if xhat is not None else None,
        "recovered_full_vector": bool(xhat is not None and np.array_equal(xhat, x)),
        "info": info,
    }


def experiment_negative_control(seed=SEED + 9):
    """
    Corrupt one recovered byte before verification: the MQ system must REFUSE to
    certify (no false accept). Confirms certification is sound, not rubber-stamping.
    """
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, N, dtype=np.uint8)
    A, b = gen_public_system(rng)
    y = mq_eval(A, b, x)
    pre_hat, unknown, sig_hat = assemble(x, 2.0, 300, 2.0, 100, rng)
    # sabotage: flip a correctly-recovered suffix byte
    sig_bad = sig_hat.copy(); sig_bad[0] ^= 0x01
    xhat, info = complete_and_verify(A, b, y, pre_hat, unknown, sig_bad)
    return {
        "sabotaged_one_suffix_byte": True,
        "certified_anything": bool(xhat is not None),   # expect False
        "accepted": info.get("accepted"),
    }


if __name__ == "__main__":
    print("=" * 76)
    print("PART 3 -- FULL-VECTOR RECOVERY  (CPA parts + MQ combine/verify/complete)")
    print("gf256-short L1: x in GF(256)^48 ; prefix via B, suffix via C ; MQ certifies")
    print("=" * 76)

    print("\n[1] Exact full-vector recovery -- noise sweep, 40 keys")
    sweep = experiment_noise_sweep()
    print(f"    {'sigma':>6} {'full-vector rec':>16} {'polarity flips':>15} "
          f"{'0-bytes done':>13} {'false certs':>12}")
    for r in sweep:
        print(f"    {r['sigma']:>6.1f} {r['full_vector_recovery_rate']*100:>15.1f}% "
              f"{r['keys_needing_polarity_flip']:>15} {r['zero_bytes_completed_total']:>13} "
              f"{r['false_certifications']:>12}")
    print(f"    unknown-count histograms (zeros per key): "
          + "; ".join(f"s{r['sigma']:.0f}:{r['unknown_count_histogram']}" for r in sweep))

    print("\n[1b] High-noise suffix budget (sigma=4): full recovery vs #suffix signatures")
    budget = experiment_suffix_budget()
    print(f"    {'n_sig_suffix':>13} {'full-vector rec':>16}")
    for r in budget:
        print(f"    {r['n_sig_suffix']:>13} {r['full_vector_recovery_rate']*100:>15.1f}%")
    print("    => the sigma=4 dip is the suffix front needing more sigs (Part-1 property), not assembly.")

    print("\n[1c] Global-polarity resolution by the MQ system")
    pol = experiment_polarity_resolution()
    print(f"    fed complemented suffix -> MQ selected '{pol['mq_selected_polarity']}' branch, "
          f"recovered full vector = {pol['recovered_full_vector']}")

    print("\n[2] Forced zero-byte completion (coord 5 set to 0)")
    fz = experiment_forced_zero()
    print(f"    coord5 flagged unknown by CPA : {fz['coord5_flagged_unknown']}")
    print(f"    MQ-completed coord5 value     : {fz['completed_value_coord5']} (true = 0)")
    print(f"    full vector recovered         : {fz['recovered_full_vector']}  (polarity={fz['info'].get('polarity')})")

    print("\n[3] Negative control -- certification soundness")
    nc = experiment_negative_control()
    print(f"    one suffix byte sabotaged -> certified anything? {nc['certified_anything']} "
          f"(expect False; accepted={nc['accepted']})")

    with open(OUT, "w") as f:
        json.dump({"noise_sweep": sweep, "suffix_budget": budget,
                   "polarity_resolution": pol, "forced_zero": fz,
                   "negative_control": nc}, f, indent=2)
    print(f"\nSaved -> {OUT}")
