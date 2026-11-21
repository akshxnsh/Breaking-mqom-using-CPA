"""
End-to-end assembly for Part 3: ONE secret x drives both CPA fronts on synthetic
leakage, producing the recovered parts and their residual ambiguities, which the
MQ system then resolves/verifies (see run_full_recovery.py).

  suffix  x[16..47]  <-  Candidate C  (vertical signed key-XOR CPA; Part 1)
  prefix  x[0..15]   <-  Candidate B  (horizontal CPA; Part 2)

Residual ambiguities handed to the algebra step (NOT resolved by CPA):
  * suffix: a SINGLE global polarity bit (sigma_hat vs sigma_hat XOR 0xFF) -- Part 1.
  * prefix: self-detected x_j = 0 bytes are left UNKNOWN (dead multiplicative channel).

All leakage is synthetic; the attacker never sees x, acc_x, rseed, or shares.
"""
import numpy as np
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from candidate_c.model_c import (simulate_observations, leak_hw, cpa_byte,
                                 N_COORDS, LAMBDA_BYTES, SUFFIX)
from candidate_b.model_b import (multiplier_stream, leak_products, cpa_coord, PREFIX)

ZERO_FLAG_THRESH = 0.30     # prefix coord flagged unknown if max|rho| below this


def recover_suffix_C(x, sigma, n_sig, rng):
    """Candidate C signed CPA on suffix coords 16..47. Returns sigma_hat (32,)."""
    delta, accx = simulate_observations(x, n_sig, rng)
    sig_hat = np.zeros(len(SUFFIX), dtype=np.uint8)
    for idx, k in enumerate(SUFFIX):
        corr = cpa_byte(delta[:, k], leak_hw(accx[:, k], sigma, rng))  # signed
        sig_hat[idx] = int(np.argmax(corr))
    return sig_hat


def recover_prefix_B(x, sigma, n_sig, rng, thresh=ZERO_FLAG_THRESH):
    """
    Candidate B horizontal CPA on prefix coords 0..15.
    Returns (pre_hat (16,), unknown_mask (16,) bool) where unknown_mask[j]=True means
    the coord was self-detected as a dead/zero channel (max|rho| < thresh).
    """
    pre_hat = np.zeros(LAMBDA_BYTES, dtype=np.uint8)
    unknown = np.zeros(LAMBDA_BYTES, dtype=bool)
    for j in PREFIX:
        mult = multiplier_stream(j, rng)
        corr = cpa_coord(mult, leak_products(int(x[j]), mult, sigma, n_sig, rng))
        if float(corr.max()) < thresh:
            unknown[j] = True          # zero/dead channel: leave for MQ completion
            pre_hat[j] = 0             # best guess, but marked unknown
        else:
            pre_hat[j] = int(np.argmax(corr))
    return pre_hat, unknown


def assemble(x, sigma_suffix, n_sig_suffix, sigma_prefix, n_sig_prefix, rng):
    """
    Run both fronts and return everything Part 3 needs:
      pre_hat (16,), unknown_mask (16,), sig_hat (32,)
    Note: sig_hat carries an unresolved global polarity bit (handled downstream).
    """
    sig_hat = recover_suffix_C(x, sigma_suffix, n_sig_suffix, rng)
    pre_hat, unknown = recover_prefix_B(x, sigma_prefix, n_sig_prefix, rng)
    return pre_hat, unknown, sig_hat


if __name__ == "__main__":
    from gf256 import HW
    rng = np.random.default_rng(20261122)
    x = rng.integers(0, 256, N_COORDS, dtype=np.uint8)
    pre_hat, unknown, sig_hat = assemble(x, 2.0, 300, 2.0, 100, rng)
    print("prefix correct (nonzero coords):",
          bool(np.all(pre_hat[~unknown] == x[:LAMBDA_BYTES][~unknown])))
    print("unknown (zero-flagged) prefix coords:", np.where(unknown)[0].tolist())
    print("suffix correct OR complemented:",
          bool(np.all(sig_hat == x[SUFFIX]) or np.all((sig_hat ^ 0xFF) == x[SUFFIX])))
