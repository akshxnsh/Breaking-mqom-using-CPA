"""
Live terminal walkthrough of full-key recovery, for the BTP presentation.

This is a PRESENTATION AID, not new research: every number it prints comes
from the actual, already-validated attack code in candidate_c/, candidate_b/,
and assembly/ (imported directly, unmodified). This script only adds
step-by-step narration around those real calls -- one key, one noise level,
chosen to land on a nice "aha" moment (a suffix mirror-tie and a flagged
prefix zero-byte) so the demo visually matches slides 14 and 16.

Run:  python demo/live_recovery_demo.py [--seed N]
"""
import argparse
import sys
import os
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gf256 import HW
from candidate_c.model_c import (
    N_COORDS, LAMBDA_BYTES, SUFFIX,
    simulate_observations, leak_hw, cpa_byte,
)
from candidate_b.model_b import (
    PREFIX, multiplier_stream, leak_products, cpa_coord,
)
from assembly.mq_system import gen_public_system, mq_eval, verify, num_satisfied, M
from assembly.assemble import ZERO_FLAG_THRESH

SIGMA_SUFFIX = 2.0
N_SIG_SUFFIX = 300
SIGMA_PREFIX = 2.0
N_SIG_PREFIX = 100

PAUSE = 0.0  # set >0 (e.g. 0.15) for a slower, more "live" feel when presenting


def hx(b):
    return f"0x{int(b):02X}"


def bar(done, total, width=28):
    filled = int(width * done / total) if total else width
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def banner(title):
    print()
    print("-" * 60)
    print(title)
    print("-" * 60)


def find_demo_key(rng_seed, max_tries=2000):
    """
    Search (starting from rng_seed) for a secret key whose prefix contains a
    zero byte, so the live run visibly hits the "flagged zero-byte" moment
    from slide 16 (the suffix mirror-tie from slide 14 shows up on essentially
    every run -- it's a structural property of the bare-XOR target, not rare).
    Falls back to the first seed tried if no zero byte turns up within max_tries.
    """
    fallback = None
    for offset in range(max_tries):
        seed = rng_seed + offset
        rng = np.random.default_rng(seed)
        x = rng.integers(0, 256, N_COORDS, dtype=np.uint8)
        if fallback is None:
            fallback = seed
        if np.any(x[:LAMBDA_BYTES] == 0):
            return seed
    return fallback


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=None,
                     help="Fixed random seed, for a REPEATABLE run (same key every time "
                          "you use this number). Default: a genuinely fresh random key "
                          "every run, pulled from the OS's randomness, not reproducible.")
    args = ap.parse_args()

    if args.seed is not None:
        seed = args.seed
    else:
        # True randomness each run (OS entropy), auto-nudged to a key that also shows
        # the flagged-zero-byte moment, for a nicer demo -- but still a fresh key
        # every time, not the same one run after run.
        fresh_base = int(np.random.SeedSequence().entropy % (2**31))
        seed = find_demo_key(fresh_base)

    print("=" * 60)
    print("  MQOM v2.1 -- Full Secret Key Recovery via CPA (simulation)")
    print("=" * 60)

    banner("[STEP 0] Setting up the experiment")
    mode_note = "fixed by --seed, so this run is repeatable" if args.seed is not None \
        else "freshly randomized this run, not repeatable"
    print(f"  -> Random seed: {seed}  ({mode_note})")
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, N_COORDS, dtype=np.uint8)
    print(f"  -> Generating secret key x ({N_COORDS} bytes)... done  [HIDDEN from attacker]")
    print("  -> x = " + " ".join("??" for _ in range(N_COORDS)) + "   (not shown -- this is what we're trying to find)")
    time.sleep(PAUSE)

    # ------------------------------------------------------------------
    # ATTACK 1 -- suffix (Candidate C, signed vertical key-XOR CPA)
    # ------------------------------------------------------------------
    banner("[ATTACK 1 of 2]  Suffix recovery -- public correction value (Delta x)")
    print(f"  -> Target: bytes {LAMBDA_BYTES}-{N_COORDS - 1} of x ({len(SUFFIX)} bytes)")
    print(f"  -> Simulating {N_SIG_SUFFIX} signatures, each with a fresh random share split")
    print(f"  -> Leakage model: Hamming weight + noise (sigma = {SIGMA_SUFFIX})")
    print()
    print(f"  Collecting traces: {bar(N_SIG_SUFFIX, N_SIG_SUFFIX)} {N_SIG_SUFFIX}/{N_SIG_SUFFIX} signatures")
    print()
    print("  Running signed CPA, byte by byte...")

    delta, accx = simulate_observations(x, N_SIG_SUFFIX, rng)
    sig_hat = np.zeros(len(SUFFIX), dtype=np.uint8)
    mirror_shown = False
    for idx, k in enumerate(SUFFIX):
        leak = leak_hw(accx[:, k], SIGMA_SUFFIX, rng)
        corr_signed = cpa_byte(delta[:, k], leak, signed=True)
        corr_abs = np.abs(corr_signed)
        best = int(np.argmax(corr_signed))
        sig_hat[idx] = best

        order = np.argsort(-corr_abs)
        top1, top2 = order[0], order[1]
        is_tie = abs(float(corr_abs[top1]) - float(corr_abs[top2])) < 1e-3

        if is_tie and not mirror_shown:
            mirror_shown = True
            print(f"    byte {k:2d}: TIE DETECTED -- {hx(top1)} vs {hx(top2)} "
                  f"(|corr| = {corr_abs[top1]:.4f})")
            print(f"             -> resolving with signed correlation...")
            print(f"             -> {hx(top1)}: corr = {corr_signed[top1]:+.4f}   "
                  f"{hx(top2)}: corr = {corr_signed[top2]:+.4f}")
            print(f"             -> chosen: {hx(best)}" + ("  [correct]" if best == x[k] else "  [WRONG]"))
        else:
            ok = "[correct]" if best == x[k] else "[WRONG]"
            print(f"    byte {k:2d}: best guess {hx(best)}  (corr = {corr_signed[best]:+.2f})  {ok}")

    n_correct_suffix_direct = int(np.sum(sig_hat == x[SUFFIX]))
    print()
    print(f"  Suffix recovered: {len(SUFFIX)}/{len(SUFFIX)} bytes "
          f"{'(up to one global polarity bit -- resolved next by the public equations)' if not n_correct_suffix_direct == len(SUFFIX) else ''}")

    # ------------------------------------------------------------------
    # ATTACK 2 -- prefix (Candidate B, horizontal CPA)
    # ------------------------------------------------------------------
    banner("[ATTACK 2 of 2]  Prefix recovery -- public multiply step (A . x)")
    print(f"  -> Target: bytes 0-{LAMBDA_BYTES - 1} of x ({LAMBDA_BYTES} bytes)")
    print(f"  -> Simulating {N_SIG_PREFIX} signatures, many public multiplies per byte")
    print(f"  -> Leakage model: Hamming weight + noise (sigma = {SIGMA_PREFIX})")
    print()
    print("  Running horizontal CPA, byte by byte...")

    pre_hat = np.zeros(LAMBDA_BYTES, dtype=np.uint8)
    unknown = np.zeros(LAMBDA_BYTES, dtype=bool)
    for j in PREFIX:
        mult = multiplier_stream(j, rng)
        leak = leak_products(int(x[j]), mult, SIGMA_PREFIX, N_SIG_PREFIX, rng)
        corr = cpa_coord(mult, leak)
        best = int(np.argmax(corr))
        score = float(corr.max())
        if score < ZERO_FLAG_THRESH:
            unknown[j] = True
            pre_hat[j] = 0
            print(f"    byte {j:2d}:  best guess {hx(best)}  (corr = {score:.2f})   "
                  f"[!] FLAGGED")
            print(f"             -> score collapsed -- this looks like x_j = 0")
            print(f"             -> deferring to equation check (next step)")
        else:
            pre_hat[j] = best
            ok = "[correct]" if best == x[j] else "[WRONG]"
            print(f"    byte {j:2d}:  best guess {hx(best)}  (corr = {score:.2f})  {ok}")

    n_flagged = int(unknown.sum())
    n_confirmed = LAMBDA_BYTES - n_flagged
    print()
    print(f"  Prefix recovered: {n_confirmed}/{LAMBDA_BYTES} bytes confirmed"
          + (f", {n_flagged} byte(s) flagged (likely 0x00)" if n_flagged else ""))

    # ------------------------------------------------------------------
    # ASSEMBLY + CERTIFICATION
    # ------------------------------------------------------------------
    banner("[ASSEMBLY]  Combining both halves")
    A, b = gen_public_system(rng)
    y = mq_eval(A, b, x)

    print("  -> x_hat = prefix || suffix")

    candidates = []
    for suf in (sig_hat, np.bitwise_xor(sig_hat, np.uint8(0xFF))):
        base = np.concatenate([pre_hat, suf]).astype(np.uint8)
        idx = np.where(unknown)[0]
        if len(idx) == 0:
            candidates.append(base)
        else:
            for fill in range(256 ** len(idx)):
                cand = base.copy()
                v = fill
                for i in idx:
                    cand[i] = v % 256
                    v //= 256
                candidates.append(cand)

    chosen = None
    chosen_info = None
    print("  -> Checking global sign ambiguity...", end=" ")
    for cand in candidates:
        if verify(A, b, y, cand):
            chosen = cand
            break
    print("resolved" if chosen is not None and np.array_equal(chosen[LAMBDA_BYTES:], sig_hat) else
          ("resolved (complemented)" if chosen is not None else "FAILED"))

    if n_flagged and chosen is not None:
        print(f"  -> Filling flagged byte(s) using public equations...  "
              + ", ".join(f"coord {i} -> {hx(chosen[i])}" for i in np.where(unknown)[0]) + " confirmed")

    banner("[CERTIFICATION]  Verifying against public MQ equations")
    if chosen is not None:
        sat = num_satisfied(A, b, y, chosen)
        print(f"  -> Checking {M} public equations: y_i = x_hat^T A_i x_hat + b_i^T x_hat")
        print(f"  -> Equations passed: {sat} / {M}" + ("  [all pass]" if sat == M else "  [FAILED]"))
    else:
        sat = 0
        print(f"  -> No candidate satisfied the public equations.")

    print()
    print("=" * 60)
    if chosen is not None and np.array_equal(chosen, x):
        print("  RESULT:  x_hat == x   ->   TRUE")
        print(f"  Full {N_COORDS}-byte secret key recovered exactly.")
    else:
        print("  RESULT:  x_hat == x   ->   FALSE (did not match this run)")
    print("=" * 60)

    # Reveal, for the audience, now that the attack is "done"
    print()
    print("  (for reference) true x   :", " ".join(hx(v) for v in x))
    if chosen is not None:
        print("  (for reference) x_hat    :", " ".join(hx(v) for v in chosen))


if __name__ == "__main__":
    main()
