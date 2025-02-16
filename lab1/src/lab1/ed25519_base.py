"""Ed25519 base implementation"""

import abc
import hashlib
from typing import Final, Literal, cast

from .curve25519 import Curve25519
from .errors import BadKeyLengthError, BadSignatureLengthError, DecompressionError


class Ed25519Point:
    """Points are represented as tuples (X, Y, Z, T) of extended coordinates,
    with x = X/Z, y = Y/Z, x*y = T/Z."""

    X: int
    Y: int
    Z: int
    T: int

    _BASE_POINT: "Ed25519Point|None" = None
    _NEUTRAL_ELEMENT: "Ed25519Point|None" = None

    def __init__(self, X: int, Y: int, Z: int, T: int) -> None:
        """Initialise Point class"""
        self.X = X
        self.Y = Y
        self.Z = Z
        self.T = T

    # important points base and neutral element
    @classmethod
    def neutral_element(cls) -> "Ed25519Point":
        """Returns the neutral element, `(0, 1, 1, 0)`."""
        if cls._NEUTRAL_ELEMENT is None:
            cls._NEUTRAL_ELEMENT = cls(0, 1, 1, 0)
        return cls._NEUTRAL_ELEMENT

    @classmethod
    def base_point(cls) -> "Ed25519Point":
        """Returns the base point G"""
        if cls._BASE_POINT is None:
            g_y = 4 * Curve25519.mod_mult_inv(5) % Curve25519.p
            g_x = cast(int, cls.recover_x(g_y, 0))
            cls._BASE_POINT = cls(g_x, g_y, 1, g_x * g_y % Curve25519.p)
        return cls._BASE_POINT

    # point operations
    def __add__(self, Q: "Ed25519Point") -> "Ed25519Point":
        """Add operator for Ed25519Points"""
        A, B = (
            (self.Y - self.X) * (Q.Y - Q.X) % Curve25519.p,
            (self.Y + self.X) * (Q.Y + Q.X) % Curve25519.p,
        )
        C, D = 2 * self.T * Q.T * Curve25519.d % Curve25519.p, 2 * self.Z * Q.Z % Curve25519.p
        E, F, G, H = B - A, D - C, D + C, B + A
        return Ed25519Point(E * F, G * H, F * G, E * H)

    def double(self) -> "Ed25519Point":
        """Double point p, to save a few operations."""
        A = pow(self.X, 2, Curve25519.p)
        B = pow(self.Y, 2, Curve25519.p)
        C = 2 * pow(self.Z, 2, Curve25519.p)
        H = A + B % Curve25519.p
        E = H - pow((self.X + self.Y), 2, Curve25519.p)
        G = A - B % Curve25519.p
        F = C + G % Curve25519.p
        return Ed25519Point(
            E * F % Curve25519.p, G * H % Curve25519.p, F * G % Curve25519.p, E * H % Curve25519.p
        )

    def __mul__(self, s: int) -> "Ed25519Point":
        """Multiply by a scalar, `s`"""
        P = self
        Q = Ed25519Point.neutral_element()
        while s > 0:
            if s & 1:
                Q += P
            P = P.double()
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
        if (self.X * Q.Z - Q.X * self.Z) % Curve25519.p != 0:
            return False
        if (self.Y * Q.Z - Q.Y * self.Z) % Curve25519.p != 0:
            return False
        return True

    # point compression operations

    @staticmethod
    def recover_x(y: int, sign: int) -> int | None:
        """Recover point's x from a given y."""
        if y >= Curve25519.p:
            return None
        x2 = (y * y - 1) * Curve25519.mod_mult_inv(Curve25519.d * y * y + 1)
        if x2 == 0:
            return None if sign else 0

        # Compute square root of x2
        x = pow(x2, (Curve25519.p + 3) // 8, Curve25519.p)

        if (x * x - x2) % Curve25519.p != 0:
            x = x * Ed25519Base.modp_sqrt_m1 % Curve25519.p

        if (x * x - x2) % Curve25519.p != 0:
            return None

        return x if x & 1 == sign else Curve25519.p - x

    def compress(self) -> bytes:
        """Compress point to byte representation"""
        z_inv = Curve25519.mod_mult_inv(self.Z)
        x = self.X * z_inv % Curve25519.p  # equivalent to X / Z
        y = self.Y * z_inv % Curve25519.p
        return (y | ((x & 1) << 255)).to_bytes(Ed25519Base.KEY_LEN, Ed25519Base.BYTE_ORDER)

    @classmethod
    def decompress(cls, s: bytes) -> "Ed25519Point | None":
        """Decompress byte representation to a point."""
        if len(s) != Ed25519Base.KEY_LEN:
            raise DecompressionError(Ed25519Base.KEY_LEN, len(s))

        y = int.from_bytes(s, Ed25519Base.BYTE_ORDER)

        sign = y >> 255
        y &= (1 << 255) - 1

        x = cls.recover_x(y, sign)
        return cls(x, y, 1, x * y % Curve25519.p) if x else None


class Ed25519Base(abc.ABC):
    """Ed25519 implementation"""

    # Square root of -1
    modp_sqrt_m1 = pow(2, (Curve25519.p - 1) // 4, Curve25519.p)

    KEY_LEN: Final = 32
    SIG_LEN: Final = 64
    BYTE_ORDER: Literal["little"] = "little"

    @staticmethod
    def _sha512(s: bytes):
        return hashlib.sha512(s).digest()

    @staticmethod
    def _sha512_mod_q(s: bytes) -> int:
        return int.from_bytes(Ed25519Base._sha512(s), Ed25519Base.BYTE_ORDER) % Curve25519.q

    @staticmethod
    def _secret_expand(secret: bytes) -> tuple[int, bytes]:
        """Splits into s_bits and prefix, and clamps s_bits to s"""
        if len(secret) != Ed25519Base.KEY_LEN:
            raise BadKeyLengthError(Ed25519Base.KEY_LEN, len(secret))
        h = Ed25519Base._sha512(secret)
        a = int.from_bytes(h[: Ed25519Base.KEY_LEN], Ed25519Base.BYTE_ORDER)
        a &= (1 << 254) - 8
        a |= 1 << 254
        return (a, h[Ed25519Base.KEY_LEN :])

    @staticmethod
    def _secret_to_public(secret: bytes) -> bytes:
        (a, _) = Ed25519Base._secret_expand(secret)
        G = Ed25519Point.base_point()
        return Ed25519Point.compress(a * G)

    @staticmethod
    def _sign(secret: bytes, msg: bytes) -> bytes:
        """Signature generating function"""
        s, prefix = Ed25519Base._secret_expand(secret)

        B = Ed25519Point.base_point()
        pk = Ed25519Point.compress(s * B)

        r = Ed25519Base._sha512_mod_q(prefix + msg)
        R = (r * B).compress()

        k = Ed25519Base._sha512_mod_q(R + pk + msg)

        t = (r + k * s) % Curve25519.q

        return R + int.to_bytes(t, Ed25519Base.KEY_LEN, Ed25519Base.BYTE_ORDER)

    @staticmethod
    def _verify(public: bytes, msg: bytes, signature: bytes) -> bool:
        """Signature verification function"""
        if (lp := len(public)) != Ed25519Base.KEY_LEN:
            raise BadKeyLengthError(Ed25519Base.KEY_LEN, lp)
        if (ls := len(signature)) != Ed25519Base.SIG_LEN:
            raise BadSignatureLengthError(Ed25519Base.SIG_LEN, ls)

        A = Ed25519Point.decompress(public)
        if not A:
            return False

        R_bits = signature[: Ed25519Base.KEY_LEN]
        R = Ed25519Point.decompress(R_bits)
        if not R:
            return False

        t = int.from_bytes(signature[Ed25519Base.KEY_LEN :], Ed25519Base.BYTE_ORDER)
        if t >= Curve25519.q:
            return False
        # so by definition t = t_bits % q

        k = Ed25519Base._sha512_mod_q(R_bits + public + msg)

        B = Ed25519Point.base_point()

        return t * B == R + k * A

    @abc.abstractmethod
    def __init__(self) -> None:
        """Abstract init"""
