"""
Independent GF(256) arithmetic for the MQOM v2.1 side-channel SIMULATION study.

This is an INDEPENDENT mathematical reimplementation of the AES/Rijndael field
GF(2^8) with reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B), the field used
by MQOM's gf256 parameter sets. It is NOT taken from, and must never be presented
as, the MQOM reference implementation. It exists only to let us model intermediate
values mathematically for synthetic-leakage experiments.

Verified below against known AES field products.
"""

import numpy as np

RED_POLY = 0x11B          # x^8 + x^4 + x^3 + x + 1
GENERATOR = 0x03          # a known primitive element of this field


def _mul_slow(a: int, b: int) -> int:
    """Carry-less (Russian-peasant) multiply in GF(2^8), reduced by 0x11B."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= (RED_POLY & 0xFF)   # reduce (0x1B is 0x11B mod 2^8)
    return p & 0xFF


def _build_tables():
    """Build log/antilog tables w.r.t. GENERATOR for fast multiply, plus a HW table."""
    exp = np.zeros(512, dtype=np.uint8)
    log = np.zeros(256, dtype=np.uint8)
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _mul_slow(x, GENERATOR)
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    hw = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)
    return exp, log, hw


EXP, LOG, HW = _build_tables()


def mul(a, b):
    """GF(256) multiply, works on scalars or numpy uint8 arrays (elementwise)."""
    a = np.asarray(a, dtype=np.uint16)
    b = np.asarray(b, dtype=np.uint16)
    out = np.zeros(np.broadcast(a, b).shape, dtype=np.uint8)
    nz = (a != 0) & (b != 0)
    la = LOG[np.where(a == 0, 0, a).astype(np.uint8)].astype(np.uint16)
    lb = LOG[np.where(b == 0, 0, b).astype(np.uint8)].astype(np.uint16)
    out[nz] = EXP[(la + lb)[nz]]
    return out if out.shape else np.uint8(out)


def hw(v):
    """Hamming weight of GF(256) byte(s)."""
    return HW[np.asarray(v, dtype=np.uint8)]


def _selftest():
    # Known AES-field products.
    assert _mul_slow(0x57, 0x83) == 0xC1, "0x57*0x83 should be 0xC1"
    assert _mul_slow(0x53, 0xCA) == 0x01, "0x53 and 0xCA are AES-field inverses"
    assert _mul_slow(0x02, 0x80) == 0x1B, "xtime(0x80) should be 0x1B"
    # Table multiply agrees with slow multiply on a random sample.
    rng = np.random.default_rng(0)
    A = rng.integers(0, 256, 5000, dtype=np.uint8)
    B = rng.integers(0, 256, 5000, dtype=np.uint8)
    fast = mul(A, B)
    slow = np.array([_mul_slow(int(x), int(y)) for x, y in zip(A, B)], dtype=np.uint8)
    assert np.array_equal(fast, slow), "table multiply disagrees with reference"
    assert HW[0xFF] == 8 and HW[0x00] == 0
    print("gf256 self-test passed: field arithmetic matches AES reference.")


if __name__ == "__main__":
    _selftest()
