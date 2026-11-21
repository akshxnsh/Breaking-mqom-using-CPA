"""
Candidate F -- correlated-tree root delta = FirstBits_128(x): independent model,
synthetic leakage, and SECOND-ORDER CPA for the MQOM v2.1 SIMULATION study.
BACKUP route to the 16-byte PREFIX (Candidate B is primary).

------------------------------------------------------------------------------
WHAT THIS MODELS  (all values SIMULATED; no physical measurement)
------------------------------------------------------------------------------
[Spec]/[Audit] blc_default.c: delta = _x[0:16] = FirstBits(x) (the first 16 bytes
of the witness, FIXED -- part of the permanent key).  ggm_tree.c:
    node2 = rseed            (FRESH uniform mask, per signature)
    node3 = node2 XOR delta  = rseed XOR delta   (masked value)
Both the mask and the masked value are manipulated in the same trace.  rseed is
SECRET/UNKNOWN and refreshed each signature => there is NO first-order known-data
handle (unlike Candidate C's public Delta_x).  Only a SECOND-ORDER (mask,
masked-value) channel against a delta-hypothesis is available.

------------------------------------------------------------------------------
IDENTIFIABILITY (the central, honest finding)  [Deduction]
------------------------------------------------------------------------------
For a uniform byte mask r and pooled Hamming-weight leakage, the centered product
of the two leakages estimates

    Cov( HW(r), HW(r XOR delta) )
      = sum_bits Cov( r_i, r_i XOR delta_i )
      = (1/4)*(#zero bits of delta) - (1/4)*(#one bits)
      = 2 - HW(delta)/2.

So the pooled-HW second-order statistic is a function of HW(delta) ONLY.  It cannot
separate two bytes with the same Hamming weight => it recovers the HW CLASS of each
prefix byte (1 of 9), not the byte (1 of 256).  With NO public per-signature input
there is also no classical correlation-over-data handle.  Hence F ALONE cannot
recover the prefix; it is a partial backup, exactly as scoped in the research plan.

If instead per-BIT leakage is available (a stronger assumption), each bit is
recoverable:  Cov( bit_i(r), bit_i(r XOR delta) ) = +1/4 if delta_i=0 else -1/4,
so the sign of the per-bit covariance gives delta bit i => full delta.  We include
this to delimit F's envelope, not as the primary realistic model.

------------------------------------------------------------------------------
ATTACKER MODEL
------------------------------------------------------------------------------
Known : synthetic leakage of node2 (mask) and node3 (masked value) per signature.
Hidden: rseed (never returned) and delta (the target).  Leakage exposes delta only
through node3 = rseed XOR delta, guarding against success-by-construction.
"""

import numpy as np
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gf256 import HW   # independent field module (root of repo)

LAMBDA_BYTES = 16      # delta = first 16 bytes of x


def gen_delta(rng):
    """The prefix delta = first 16 key bytes [simulation input]."""
    return rng.integers(0, 256, LAMBDA_BYTES, dtype=np.uint8)


def tree_shares(delta_byte, n_sig, rng):
    """Per-signature (mask, masked value) for one delta byte. rseed stays hidden."""
    rseed = rng.integers(0, 256, n_sig, dtype=np.uint8)
    node3 = np.bitwise_xor(rseed, np.uint8(delta_byte))
    return rseed, node3


def leak_pooled_hw(node2, node3, sigma, rng):
    """L2 = HW(rseed)+noise, L3 = HW(rseed^delta)+noise.  [Assumption]"""
    L2 = HW[node2].astype(np.float64) + rng.normal(0, sigma, size=node2.shape)
    L3 = HW[node3].astype(np.float64) + rng.normal(0, sigma, size=node3.shape)
    return L2, L3


def leak_bitlevel(node2, node3, sigma, rng):
    """Per-bit leakage of mask and masked value: (n_sig x 8) arrays.  [Assumption, stronger]"""
    b2 = ((node2[:, None] >> np.arange(8)) & 1).astype(np.float64)
    b3 = ((node3[:, None] >> np.arange(8)) & 1).astype(np.float64)
    if sigma > 0:
        b2 += rng.normal(0, sigma, size=b2.shape)
        b3 += rng.normal(0, sigma, size=b3.shape)
    return b2, b3


# ----------------------------------------------------------------------------
# Second-order distinguishers
# ----------------------------------------------------------------------------
def so_hw_estimate(L2, L3):
    """Pooled-HW second-order: Cov -> HW(delta) via HW_est = 4 - 2*Cov."""
    cov = float(np.mean((L2 - L2.mean()) * (L3 - L3.mean())))
    return cov, 4.0 - 2.0 * cov


def so_bits_recover(b2, b3):
    """Bit-level second-order: sign of per-bit covariance gives each delta bit."""
    covs = np.mean((b2 - b2.mean(axis=0)) * (b3 - b3.mean(axis=0)), axis=0)
    bits = (covs < 0).astype(np.uint8)           # negative cov => delta bit = 1
    delta = int(sum(int(bits[i]) << i for i in range(8)))
    return delta, covs


def hw_class_size(h):
    from math import comb
    return comb(8, int(h))
