"""Pure-Python RFC 8032 Ed25519 key derivation, signing, and verification (zero C deps)."""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)

ExtPoint = tuple[int, int, int, int]


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _xrecover(_BY)
_B: ExtPoint = (_BX % _P, _BY % _P, 1, (_BX * _BY) % _P)
_IDENTITY: ExtPoint = (0, 1, 1, 0)


def _point_add(pt_p: ExtPoint, pt_q: ExtPoint) -> ExtPoint:
    x1, y1, z1, t1 = pt_p
    x2, y2, z2, t2 = pt_q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mult(pt: ExtPoint, scalar: int) -> ExtPoint:
    res = _IDENTITY
    cur = pt
    k = scalar
    while k > 0:
        if k & 1:
            res = _point_add(res, cur)
        cur = _point_add(cur, cur)
        k >>= 1
    return res


def _encode_point(pt: ExtPoint) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _P - 2, _P)
    xp = (x * zi) % _P
    yp = (y * zi) % _P
    bits = yp | ((xp & 1) << 255)
    return bits.to_bytes(32, "little")


def _decode_point(enc: bytes) -> ExtPoint:
    if len(enc) != 32:
        raise ValueError("Ed25519 public key / R point must be 32 bytes")
    val = int.from_bytes(enc, "little")
    y = val & ((1 << 255) - 1)
    x_sign = (val >> 255) & 1
    if y >= _P:
        raise ValueError("Invalid Ed25519 y coordinate >= p")
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("Point is not on Ed25519 curve")
    if x == 0 and x_sign == 1:
        raise ValueError("Invalid negative zero x coordinate")
    if (x & 1) != x_sign:
        x = _P - x
    return (x, y, 1, (x * y) % _P)


def _clamp_scalar(digest_low32: bytes) -> int:
    arr = bytearray(digest_low32)
    arr[0] &= 248
    arr[31] &= 127
    arr[31] |= 64
    return int.from_bytes(arr, "little")


def derive_public_key(seed: bytes) -> bytes:
    """Derive 32-byte RFC 8032 Ed25519 public key from 32-byte secret seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 secret seed must be exactly 32 bytes")
    h = hashlib.sha512(seed).digest()
    s = _clamp_scalar(h[:32])
    return _encode_point(_scalar_mult(_B, s))


def sign_ed25519(seed: bytes, message: bytes) -> bytes:
    """Produce deterministic 64-byte RFC 8032 Ed25519 signature."""
    if len(seed) != 32:
        raise ValueError("Ed25519 secret seed must be exactly 32 bytes")
    h = hashlib.sha512(seed).digest()
    s = _clamp_scalar(h[:32])
    prefix = h[32:]
    pub = _encode_point(_scalar_mult(_B, s))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    r_bytes = _encode_point(_scalar_mult(_B, r))
    k = int.from_bytes(hashlib.sha512(r_bytes + pub + message).digest(), "little") % _L
    s_scalar = (r + k * s) % _L
    return r_bytes + s_scalar.to_bytes(32, "little")


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify 64-byte RFC 8032 Ed25519 signature (strict s < L malleability guard)."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    r_bytes = signature[:32]
    s_scalar = int.from_bytes(signature[32:], "little")
    if s_scalar >= _L:
        return False
    try:
        pt_a = _decode_point(public_key)
        pt_r = _decode_point(r_bytes)
    except ValueError:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
    lhs = _scalar_mult(_B, s_scalar)
    rhs = _point_add(pt_r, _scalar_mult(pt_a, k))
    return _encode_point(lhs) == _encode_point(rhs)
