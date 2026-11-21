"""
Candidate B -- ComputePz / compute_t1 matrix-vector product: independent model,
synthetic leakage, and HORIZONTAL CPA for the MQOM v2.1 side-channel SIMULATION
study.  This is the PRIMARY route to the 16-byte PREFIX x[0..15] (Part 2).

------------------------------------------------------------------------------
WHAT THIS MODELS  (all values are SIMULATED; no physical measurement anywhere)
------------------------------------------------------------------------------
[Spec]/[Audit] MQOM v2.1 reference (commit b8879fe), piop_default.c compute_t1:

    t1_i = Ahat_i . x + bhat_i          (per signature)

Ahat is the PUBLIC ext-field matrix (expanded from mseed_eq in the public key);
x is the SECRET base-field witness.  Both are FIXED across signatures, so with
USE_PIOP_CACHE the product is recomputed identically every Sign() -> the identical
intermediates recur => leakage can be VERTICALLY AVERAGED across signatures.

[Audit] The ext-by-base product is byte-serial (gf256to2_gf256_mat_mult_ref ->
gf256_gf256to2_vect_mult_ref -> scalar gf256_mult_ref, hi/lo byte), NOT SWAR-packed,
so byte-level leakage is not blurred.  The TRI_INF (lower-triangular) structure makes
secret coordinate x_j appear in many rows: ~ mhat*(N-j)*2 scalar multiplies per
signature.  So within ONE trace, x_j (fixed) meets MANY distinct PUBLIC multipliers
Ahat-entries (XOF output -> modelled uniform over GF(256)).  That is the HORIZONTAL
variation axis Candidate B offers for EVERY coordinate, prefix included.

------------------------------------------------------------------------------
WHY THIS REACHES THE PREFIX (which Candidate C cannot)
------------------------------------------------------------------------------
Candidate C needs a public per-signature varying value (Delta_x), which is zero on
the prefix.  Candidate B needs no such thing: the known-varying data are the PUBLIC
multipliers Ahat_i[r][j], which are plentiful and non-trivial for EVERY coordinate,
prefix bytes 0..15 included.  Hence B is the primary prefix route.

------------------------------------------------------------------------------
ATTACKER MODEL  (the guard against "success by construction")
------------------------------------------------------------------------------
Known to attacker : the PUBLIC multipliers a = Ahat_i[r][j] meeting x_j (per position)
                    the SYNTHETIC leakage L of the secret-dependent product x_j * a
Secret (hidden)   : x_j (the permanent key byte)
Leakage hypothesis: L_pos = phi( gf256_mult(x_j, a_pos) ) + noise      [Assumption]
The attacker predicts phi(gf256_mult(g, a_pos)) for each guess g and correlates over
positions; it never receives x, acc_x, or shares.  Leakage depends on x_j ONLY through
the real field product (no direct leak of x_j), guarding success-by-construction.
"""

import numpy as np
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gf256 import mul, HW   # independent field module (root of repo)

# ----------------------------------------------------------------------------
# Parameters for the gf256-short L1 parameter set [Spec, Table 6 / Audit]
# ----------------------------------------------------------------------------
N_COORDS = 48          # witness length n over GF(256)
MHAT = 24              # packed ext rows (gf256-short L1)
LAMBDA_BYTES = 16      # prefix = first 16 bytes (the Part-2 target)
PREFIX = np.arange(0, LAMBDA_BYTES)

# Model-side prediction table HWPRED[g, a] = HW( g * a ). Built once from the
# independent field module.  (256 x 256 float.)
_G = np.arange(256, dtype=np.uint8)
HWPRED = HW[mul(_G[:, None], _G[None, :])].astype(np.float64)

# A realistic bit-weight table and a NON-MONOTONE stress table for mismatch runs.
_BITS = ((np.arange(256)[:, None] >> np.arange(8)) & 1).astype(np.float64)   # 256x8
WEIGHTS_REALISTIC = np.array([1.00, 1.10, 0.95, 1.20, 0.90, 1.15, 1.05, 0.85])
WEIGHTS_NONMONOTONE = np.array([1.00, 1.10, 0.95, -1.20, 0.90, 1.15, 1.05, 0.85])
PHI_HW = HW.astype(np.float64)
PHI_WHW = (_BITS * WEIGHTS_REALISTIC[None, :]).sum(axis=1)       # monotone (all w>0)
PHI_NONMONO = (_BITS * WEIGHTS_NONMONOTONE[None, :]).sum(axis=1)  # STRESS TEST ONLY


def gen_secret(rng):
    """A random permanent witness x in GF(256)^48 [simulation input]."""
    return rng.integers(0, 256, N_COORDS, dtype=np.uint8)


def positions_for_coord(j):
    """# byte-serial gf256 multiplies x_j participates in per signature = mhat*(N-j)*2."""
    return MHAT * (N_COORDS - j) * 2


def multiplier_stream(j, rng):
    """PUBLIC multipliers (one per horizontal position) meeting x_j; XOF -> uniform."""
    return rng.integers(0, 256, size=positions_for_coord(j), dtype=np.uint8)


def leak_products(xj, multipliers, sigma, n_sig, rng, phi=PHI_HW):
    """
    Synthetic horizontal leakage of the secret-dependent products p = x_j * a,
    vertically averaged over n_sig signatures (identical intermediates recur).
    Effective per-position noise = sigma / sqrt(n_sig).  [Assumption]
    """
    prod = mul(np.uint8(xj), multipliers)             # secret-dependent intermediate
    base = phi[prod].astype(np.float64)
    if sigma > 0 and n_sig > 0:
        base = base + rng.normal(0.0, sigma / np.sqrt(n_sig), size=base.shape)
    return base


# ----------------------------------------------------------------------------
# Horizontal CPA on one coordinate
# ----------------------------------------------------------------------------
def cpa_coord(multipliers, leak):
    """
    Horizontal Pearson CPA on one coordinate.
      multipliers : (P,) public multipliers (uint8)
      leak        : (P,) synthetic leakage over positions
    Returns corr_abs[256] (|Pearson| per guess).  Field multiply is a bijection in
    the guess, so the correct byte gives the unique max under full multiplier
    coverage (no complement ambiguity -- unlike the additive suffix target).
    """
    pred = HWPRED[:, multipliers]                      # (256, P)
    pc = pred - pred.mean(axis=1, keepdims=True)
    Lc = leak - leak.mean()
    num = pc @ Lc
    den = np.sqrt((pc * pc).sum(axis=1) * (Lc * Lc).sum()) + 1e-12
    return np.abs(num / den)


def rank_of_true(corr, true_key):
    order = np.argsort(-corr, kind="stable")
    return int(np.where(order == true_key)[0][0])


def alias_profile_noiseless(true_byte, multipliers):
    """
    Noiseless |rho|(g).  [Deduction] rho(g) depends only on c = g * x^{-1}:
    rho(c) = corr_a( HW(a), HW(c*a) ), so the correct key (c=1) is the unique max
    iff no c!=1 makes HW(c*a) affine in HW(a) -- which only c=1 does.
    """
    L_clean = HWPRED[true_byte, multipliers]
    return cpa_coord(multipliers, L_clean)
