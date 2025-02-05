"""Ed25519 base implementation"""

import functools
import hashlib
from typing import cast

from .x25519_base import X25519Base


class DecompressionError(ValueError):
    """Point decompression error"""


class BadKeyLengthError(ValueError):
    """Key expansion error"""


class BadSignatureLengthError(ValueError):
    """Signature expansion error"""


class Ed25519Point:
    """Points are represented as tuples (X, Y, Z, T) of extended coordinates,
    with x = X/Z, y = Y/Z, x*y = T/Z."""

    X: int
    Y: int
    Z: int
    T: int

    def __init__(self, X: int, Y: int, Z: int, T: int) -> None:
        """Initialise Point class"""
        self.X = X
        self.Y = Y
        self.Z = Z
        self.T = T

    # important point
    @classmethod
    def neutral_element(cls) -> "Ed25519Point":
        """Returns the neutral element, `(0, 1, 1, 0)`."""
        return cls(0, 1, 1, 0)

    # cached to speed up execution
    @classmethod
    @functools.cache
    def base_point(cls) -> "Ed25519Point":
        """Returns the base point G"""
        g_y = 4 * Ed25519Base._mod_mult_inv(5) % X25519Base.p
        g_x = cast(int, cls.recover_x(g_y, 0))
        return cls(g_x, g_y, 1, g_x * g_y % X25519Base.p)

    # point operations
    def __add__(self, Q: "Ed25519Point") -> "Ed25519Point":
        """Add operator"""
        A, B = (
            (self.Y - self.X) * (Q.Y - Q.X) % Ed25519Base.p,
            (self.Y + self.X) * (Q.Y + Q.X) % Ed25519Base.p,
        )
        C, D = 2 * self.T * Q.T * Ed25519Base.d % Ed25519Base.p, 2 * self.Z * Q.Z % Ed25519Base.p
        E, F, G, H = B - A, D - C, D + C, B + A
        return Ed25519Point(E * F, G * H, F * G, E * H)

    def _double(self) -> "Ed25519Point":
        A = self.X * self.X % Ed25519Base.p
        B = self.Y * self.Y % Ed25519Base.p
        Ch = self.Z * self.Z % Ed25519Base.p
        C = Ch + Ch % Ed25519Base.p
        H = A + B % Ed25519Base.p
        xys = self.X + self.Y % Ed25519Base.p
        E = H - xys * xys % Ed25519Base.p
        G = A - B % Ed25519Base.p
        F = C + G % Ed25519Base.p
        return Ed25519Point(
            E * F % Ed25519Base.p, G * H % Ed25519Base.p, F * G % Ed25519Base.p, E * H % Ed25519Base.p
        )

    def __mul__(self, s: int) -> "Ed25519Point":
        """Multiply by a scalar, `s`"""
        P = self
        Q = Ed25519Point.neutral_element()
        while s > 0:
            if s & 1:
                Q += P
            P = P._double()
            s >>= 1
        return Q

    def __rmul__(self, s: int) -> "Ed25519Point":
        """Right multiplication to allow commutativity with scalar, i.e. s * P = P * s."""
        return self.__mul__(s)

    def __eq__(self, Q: object) -> bool:
        """Calculate equality, using the following identity
        x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1"""

        if not isinstance(Q, Ed25519Point):
            return False
        if (self.X * Q.Z - Q.X * self.Z) % Ed25519Base.p != 0:
            return False
        if (self.Y * Q.Z - Q.Y * self.Z) % Ed25519Base.p != 0:
            return False
        return True

    # point compression operations

    @staticmethod
    def recover_x(y: int, sign: int) -> int | None:
        """Recover point's x from a given y."""
        if y >= Ed25519Base.p:
            return None
        x2 = (y * y - 1) * Ed25519Base._mod_mult_inv(Ed25519Base.d * y * y + 1)
        if x2 == 0:
            if sign:
                return None
            else:
                return 0

        # Compute square root of x2
        x = pow(x2, (Ed25519Base.p + 3) // 8, Ed25519Base.p)

        if (x * x - x2) % Ed25519Base.p != 0:
            x = x * Ed25519Base.modp_sqrt_m1 % Ed25519Base.p

        if (x * x - x2) % Ed25519Base.p != 0:
            return None

        if (x & 1) != sign:
            x = Ed25519Base.p - x
        return x

    def compress(self) -> bytes:
        """Compress point to byte representation"""
        z_inv = Ed25519Base._mod_mult_inv(self.Z)
        x = self.X * z_inv % Ed25519Base.p  # equivalent to X / Z
        y = self.Y * z_inv % Ed25519Base.p
        return (y | ((x & 1) << 255)).to_bytes(Ed25519Base.ALLOWED_LEN, "little")

    @classmethod
    def decompress(cls, s: bytes) -> "Ed25519Point | None":
        """Decompress byte representation to a point."""
        if len(s) != Ed25519Base.ALLOWED_LEN:
            raise DecompressionError("Invalid input length for decompression")

        y = int.from_bytes(s, "little")

        sign = y >> 255
        y &= (1 << 255) - 1

        x = cls.recover_x(y, sign)
        if x is None:
            return None
        else:
            return cls(x, y, 1, x * y % Ed25519Base.p)


class Ed25519Base(X25519Base):
    """Ed25519 implementation"""

    # Alias prime p
    p = X25519Base.p

    # Curve constant
    d = -121665 * X25519Base._mod_mult_inv(121666) % p

    # Group order
    q = 2**252 + 27742317777372353535851937790883648493

    # Square root of -1
    modp_sqrt_m1 = pow(2, (p - 1) // 4, p)

    @staticmethod
    def _sha512(s: bytes):
        return hashlib.sha512(s).digest()

    @staticmethod
    def _sha512_mod_q(s: bytes) -> int:
        return int.from_bytes(Ed25519Base._sha512(s), "little") % Ed25519Base.q

    @staticmethod
    def _secret_expand(secret: bytes) -> tuple[int, bytes]:
        """Splits into s_bits and prefix, and clamps s_bits to s"""
        if len(secret) != 32:
            raise BadKeyLengthError("Bad length of private key")
        h = Ed25519Base._sha512(secret)
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        return (a, h[32:])

    @staticmethod
    def _secret_to_public(secret: bytes) -> bytes:
        (a, _) = Ed25519Base._secret_expand(secret)
        G = Ed25519Point.base_point()
        return Ed25519Point.compress(a * G)

    ## The signature function works as below.
    @staticmethod
    def _sign(secret: bytes, msg: bytes) -> bytes:
        s, prefix = Ed25519Base._secret_expand(secret)

        B = Ed25519Point.base_point()
        pk = Ed25519Point.compress(s * B)

        r = Ed25519Base._sha512_mod_q(prefix + msg)
        R = (r * B).compress()

        k = Ed25519Base._sha512_mod_q(R + pk + msg)

        t = (r + k * s) % Ed25519Base.q

        return R + int.to_bytes(t, 32, "little")

    ## And finally the verification function.
    @staticmethod
    def _verify(public: bytes, msg: bytes, signature: bytes) -> bool:
        if len(public) != 32:
            raise BadKeyLengthError("Bad public key length")
        if len(signature) != 64:
            raise BadSignatureLengthError("Bad signature length")

        A = Ed25519Point.decompress(public)
        if not A:
            return False

        R_bits = signature[:32]
        R = Ed25519Point.decompress(R_bits)
        if not R:
            return False

        t = int.from_bytes(signature[32:], "little")
        if t >= Ed25519Base.q:
            return False
        # so by definition t = t_bits % q

        k = Ed25519Base._sha512_mod_q(R_bits + public + msg)

        B = Ed25519Point.base_point()

        return t * B == R + k * A
