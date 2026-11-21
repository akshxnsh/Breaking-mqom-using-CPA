"""
Independent model of the MQOM v2.1 PUBLIC MQ relation, for Part 3 (assembly +
verification).  SIMULATION only; no reference implementation.

[Spec] The public key fixes a multivariate-quadratic map and its image at the secret:
    y_i = x^T A_i x + b_i^T x        for i = 1 .. m    (over GF(256))
with A_i, b_i PUBLIC (expanded from mseed_eq) and y PUBLIC.  gf256-short L1: n = 48
unknowns, m = 48 equations.  A_i is taken upper-triangular WLOG (the quadratic form
x^T A x only sees the symmetric part; folding into upper-triangular loses nothing).

ROLE IN THE PROJECT (integrity):  algebra is used ONLY to COMBINE / VERIFY / COMPLETE
CPA-recovered parts -- never as the primary recovery mechanism.  Here it (1) certifies
an assembled x_hat by checking y_i = x_hat^T A_i x_hat + b_i^T x_hat for all i, (2)
resolves Part-1's single global polarity bit, and (3) completes the rare self-detected
x_j = 0 prefix byte(s).  The 48 bytes themselves are recovered by CPA (Parts 1-2).
"""

import numpy as np
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gf256 import mul

N = 48       # unknowns
M = 48       # equations


def gen_public_system(rng):
    """
    Public MQ system: A (M,N,N) upper-triangular, b (M,N), both uniform over GF(256).
    Returns (A, b).  These are PUBLIC (attacker/verifier both know them).
    """
    A = rng.integers(0, 256, size=(M, N, N), dtype=np.uint8)
    iu = np.triu_indices(N)
    mask = np.zeros((N, N), dtype=np.uint8)
    mask[iu] = 1
    A = A * mask[None, :, :]                 # keep upper triangle only
    b = rng.integers(0, 256, size=(M, N), dtype=np.uint8)
    return A, b


def mq_eval(A, b, x):
    """
    Evaluate y_i = x^T A_i x + b_i^T x over GF(256).  Vectorised over all M equations.
    x : (N,) uint8.  Returns y : (M,) uint8.
    """
    x = x.astype(np.uint8)
    outer = mul(x[:, None], x[None, :])              # (N,N):  x_j * x_k
    quad_terms = mul(A, outer[None, :, :])           # (M,N,N): A_i[j,k] * x_j * x_k
    quad = np.bitwise_xor.reduce(quad_terms.reshape(A.shape[0], -1), axis=1)  # XOR-sum
    lin_terms = mul(b, x[None, :])                   # (M,N)
    lin = np.bitwise_xor.reduce(lin_terms, axis=1)
    return np.bitwise_xor(quad, lin).astype(np.uint8)


def mq_eval_batch(A, b, X, chunk=2048):
    """
    Evaluate the MQ system for a BATCH of candidate vectors.
    X : (K, N) uint8.  Returns Y : (K, M) uint8.  Chunked over K to bound memory.
    Used by Part-3 completion to brute-fill rare self-detected zero bytes fast.
    """
    X = X.astype(np.uint8)
    K = X.shape[0]
    out = np.zeros((K, A.shape[0]), dtype=np.uint8)
    for s in range(0, K, chunk):
        Xc = X[s:s + chunk]                                  # (k, N)
        outer = mul(Xc[:, :, None], Xc[:, None, :])          # (k, N, N)
        quad = np.bitwise_xor.reduce(
            mul(A[None], outer[:, None]).reshape(Xc.shape[0], A.shape[0], -1), axis=2)
        lin = np.bitwise_xor.reduce(mul(b[None], Xc[:, None, :]), axis=2)
        out[s:s + chunk] = np.bitwise_xor(quad, lin)
    return out


def keygen(rng):
    """Generate a full instance: secret x, public (A, b), and public image y."""
    x = rng.integers(0, 256, size=N, dtype=np.uint8)
    A, b = gen_public_system(rng)
    y = mq_eval(A, b, x)
    return x, A, b, y


def verify(A, b, y, xhat):
    """True iff x_hat satisfies the whole public MQ system (certifies full recovery)."""
    return bool(np.array_equal(mq_eval(A, b, xhat), y))


def num_satisfied(A, b, y, xhat):
    """How many of the M equations x_hat satisfies (diagnostic)."""
    return int(np.sum(mq_eval(A, b, xhat) == y))


if __name__ == "__main__":
    rng = np.random.default_rng(20261122)
    x, A, b, y = keygen(rng)
    assert verify(A, b, y, x), "true secret must satisfy its own public system"
    # A wrong vector must fail (overwhelmingly): flip one byte.
    xbad = x.copy(); xbad[7] ^= 0x01
    sat = num_satisfied(A, b, y, xbad)
    print(f"true x: verifies = {verify(A, b, y, x)}")
    print(f"x with 1 byte flipped: {sat}/{M} eqns satisfied, verifies = {verify(A, b, y, xbad)}")
    # random wrong vector
    xr = rng.integers(0, 256, N, dtype=np.uint8)
    print(f"random vector: {num_satisfied(A, b, y, xr)}/{M} eqns satisfied (expect ~M/256)")
