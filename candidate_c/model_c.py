"""
Candidate C -- Correction value Delta_x(1): independent model, synthetic leakage,
and vertical key-XOR CPA for the MQOM v2.1 side-channel SIMULATION study.

------------------------------------------------------------------------------
WHAT THIS MODELS  (all values are SIMULATED; no physical measurement anywhere)
------------------------------------------------------------------------------
Specification-established facts [Spec], MQOM v2.1 (Benadjila-Bouillaguet-Feneuil-Rivain),
sec 2.1.3 / Eq.4 / sec 2.5.6 / Alg. 11:

    Delta_x = x XOR acc_x,     acc_x = sum_i xbar_i   (sum of fresh per-signature shares)

For the serialized suffix coordinates k >= lambda/8 (= 16 at L1), the correction
Delta_x(1)[k] is PUBLIC and VARIES per signature, and:

    acc_x[k] = x[k] XOR Delta_x(1)[k]

The prefix coordinates k < 16 have Delta_x[k] = 0 by the correlated-tree construction,
so they carry no varying public data -> no Candidate-C handle (that is Candidate F).

------------------------------------------------------------------------------
ATTACKER MODEL  (the guard against "success by construction")
------------------------------------------------------------------------------
Known to attacker : the PUBLIC per-signature value Delta_x(1)[k]      (from the signature)
                    the SYNTHETIC leakage L[k] of the secret operand acc_x[k]
Secret (hidden)   : x[k]  (the permanent key byte; fixed across signatures)
                    acc_x[k], the share sum (fresh per signature; never given to attacker)

Hypothetical leakage of the secret operand acc_x[k] at the moment the correction is formed:

    L[k]^(s) = phi( acc_x[k]^(s) ) + noise          [Assumption -- a leakage hypothesis]
             = phi( x[k] XOR Delta_x(1)[k]^(s) ) + noise

with phi = Hamming weight for the baseline model. The attacker never receives acc_x or x;
it must distinguish x[k] from all 256 hypotheses purely by correlation. This is the
textbook key-XOR CPA setup (cf. AES first-round k XOR p), here with a LINEAR (XOR) target
and therefore weaker selectivity ("ghost peaks") than an S-box target -- an honest limit
we will measure, not hide.
"""

import numpy as np
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gf256 import hw, HW   # independent field module


# ----------------------------------------------------------------------------
# Parameters for the gf256-short L1 parameter set [Spec, Table 6]
# ----------------------------------------------------------------------------
N_COORDS = 48          # witness length n over GF(256)
LAMBDA_BYTES = 16      # lambda/8 = 128/8; prefix bytes forced to zero in Delta_x
SUFFIX = np.arange(LAMBDA_BYTES, N_COORDS)   # attackable coords k = 16..47 (32 bytes)


# ----------------------------------------------------------------------------
# Independent model: secret key and per-signature observations
# ----------------------------------------------------------------------------
def gen_secret(rng):
    """A random permanent witness x in GF(256)^48 [simulation input, category 4/5]."""
    return rng.integers(0, 256, N_COORDS, dtype=np.uint8)


def simulate_observations(x, n_sig, rng):
    """
    Generate n_sig independent per-signature observations.

    acc_x suffix is modelled as fresh uniform GF(256) (a sum of many fresh pseudorandom
    shares is uniform), so Delta_x(1) = x XOR acc_x is public and varies per signature.

    Returns
      delta : (n_sig, 48) public correction; prefix forced 0, suffix = x XOR acc_x
      accx  : (n_sig, 48) the SECRET share sum (leaks; never handed to the attacker)
    """
    accx = rng.integers(0, 256, size=(n_sig, N_COORDS), dtype=np.uint8)
    # Prefix: correlated tree forces Delta_x = 0  =>  acc_x[prefix] = x[prefix] (constant).
    accx[:, :LAMBDA_BYTES] = x[:LAMBDA_BYTES]
    delta = accx ^ x[None, :]           # Delta_x = x XOR acc_x  (XOR == GF(256) add)
    return delta, accx


def leak_hw(accx_col, sigma, rng):
    """Baseline synthetic leakage: L = HW(acc_x) + Gaussian(0, sigma). [Assumption]"""
    return hw(accx_col).astype(np.float64) + rng.normal(0.0, sigma, size=accx_col.shape)


# ----------------------------------------------------------------------------
# Vertical key-XOR CPA on a single coordinate
# ----------------------------------------------------------------------------
_GUESSES = np.arange(256, dtype=np.uint8)

def cpa_byte(delta_col, leak_col, signed=True):
    """
    Pearson-correlation CPA for one coordinate.
      delta_col : (n_sig,) public Delta_x(1)[k] per signature
      leak_col  : (n_sig,) synthetic leakage of acc_x[k]
      signed    : if True return the SIGNED correlation (correct under the stated
                  "leakage grows with HW" hypothesis); if False return |correlation|.
    Returns corr[256] for each key hypothesis g.
    Prediction for hypothesis g: HW(g XOR Delta_x(1)[k]) = HW(predicted acc_x).

    NOTE ON POLARITY / THE COMPLEMENT AMBIGUITY:
      For a bare-XOR target under any affine-in-bits leakage phi, the complement key
      g' = x XOR 0xFF predicts phi(x_bar XOR d) = C - phi(x XOR d), perfectly
      anti-correlated with the true leakage. So |corr| ties x with x_bar (a 1-bit,
      2-way ambiguity). Using the SIGNED correlation under the assumed positive-HW
      polarity resolves it: true key -> +rho, complement -> -rho.
    """
    pred = HW[_GUESSES[:, None] ^ delta_col[None, :].astype(np.uint8)].astype(np.float64)  # (256, n_sig)
    pred -= pred.mean(axis=1, keepdims=True)
    L = leak_col - leak_col.mean()
    num = pred @ L
    den = np.sqrt((pred**2).sum(axis=1) * (L**2).sum()) + 1e-12
    corr = num / den
    return corr if signed else np.abs(corr)


def rank_of_true(corr, true_key):
    """Rank of the true key (0 = top-1 / recovered)."""
    order = np.argsort(-corr, kind="stable")
    return int(np.where(order == true_key)[0][0])
