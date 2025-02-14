"""Implementation for X25519's base class."""

import abc
from typing import Final, Literal, Sequence, overload

from .curve25519 import Curve25519
from .errors import DecodeSizeError

type UZProjectivePoint = tuple[int, int]

type DecodeInput = str | list[int] | bytes | int


class X25519Base(abc.ABC):
    """Implements X25519"""

    BITS: Final = 255
    ALLOWED_LEN: Final = 32
    BYTE_ORDER: Literal["little"] = "little"

    @staticmethod
    def _decode_little_endian(b: bytes | Sequence[int]):
        """Decodes a list of bytes (little-endian) into an int."""
        return sum([b[i] << 8 * i for i in range(X25519Base.ALLOWED_LEN)])

    @staticmethod
    def _decode_u_coordinate(u: DecodeInput) -> int:
        """Decode string representation of coordinate.

        Raises `DecodeSizeError` if input is invalid."""
        u_list = X25519Base._decode_input_to_list_int(u)
        u_list[-1] &= (1 << (X25519Base.BITS % 8)) - 1
        return X25519Base._decode_little_endian(u_list)

    @overload
    @staticmethod
    def _encode_u_coordinate(u: int, *, to_str: Literal[True]) -> str: ...

    @overload
    @staticmethod
    def _encode_u_coordinate(u: int, *, to_str: Literal[False]) -> bytes: ...

    @staticmethod
    def _encode_u_coordinate(u: int, *, to_str: bool) -> str | bytes:
        """Encodes u coordinate into bytes or hex string (if `to_str is True`)."""
        u = u % Curve25519.p
        x = u.to_bytes(X25519Base.ALLOWED_LEN, X25519Base.BYTE_ORDER)
        return x.hex() if to_str else x

    @staticmethod
    def _decode_input_to_list_int(x: DecodeInput) -> list[int]:
        """Decodes of type decodeinput to list int (bytes)"""

        def validate_length(c: bytes | list) -> None:
            length = len(c)
            if length != X25519Base.ALLOWED_LEN:
                raise DecodeSizeError(X25519Base.ALLOWED_LEN, length)

        if isinstance(x, str):
            bs = bytes.fromhex(x)
            validate_length(bs)
            return list(bs)

        if isinstance(x, list):
            validate_length(x)
            return [z & 0xFF for z in x]

        if isinstance(x, int):
            try:
                return list(x.to_bytes(X25519Base.ALLOWED_LEN, X25519Base.BYTE_ORDER))
            except OverflowError as e:
                raise DecodeSizeError(X25519Base.ALLOWED_LEN, (x.bit_length() + 7) // 8) from e

        # x must be bytes
        validate_length(x)
        return list(x)

    @staticmethod
    def _decode_scalar(k: DecodeInput) -> int:
        """Decodes a scalar into a little endian int, i.e. puts to list of ints (bytes) and clamps.

        Raises `DecodeSizeError` if input has invalid length."""
        k_list = X25519Base._decode_input_to_list_int(k)

        # clamp bytes
        k_list[0] &= 248
        k_list[31] &= 127
        k_list[31] |= 64

        return X25519Base._decode_little_endian(k_list)

    @staticmethod
    def _const_time_swap[T](a: T, b: T, swap: int) -> tuple[T, T]:
        """Swap two values in constant time. Base: https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3."""
        index = int(swap) * 2
        temp = (a, b, b, a)
        return temp[index], temp[index + 1]

    @staticmethod
    def _compute_x25519_ladder(k_d: DecodeInput, u_d: DecodeInput) -> int:
        """Compute value of x25519. Source: RFC.

        Args:
            k_d (decode type): scalar argument
            u_d (decode type): u coordinate

        Returns:
            int: result as an int
        """
        k = X25519Base._decode_scalar(k_d)
        u = X25519Base._decode_u_coordinate(u_d)

        P = Curve25519.p

        x_1 = u % P
        x_2 = 1
        z_2 = 0
        x_3 = u % P
        z_3 = 1
        swap = 0

        for t in reversed(range(X25519Base.BITS)):
            k_t = (k >> t) & 1
            swap ^= k_t

            x_2, x_3 = X25519Base._const_time_swap(x_2, x_3, swap)
            z_2, z_3 = X25519Base._const_time_swap(z_2, z_3, swap)

            swap = k_t

            A = (x_2 + z_2) % P
            AA = (A**2) % P
            B = (x_2 - z_2) % P
            BB = (B**2) % P
            E = (AA - BB) % P
            C = (x_3 + z_3) % P
            D = (x_3 - z_3) % P
            DA = (D * A) % P
            CB = (C * B) % P

            x_3 = pow((DA + CB) % P, 2, P)

            z_3 = x_1 * pow((DA - CB) % P, 2, P)
            z_3 %= P

            x_2 = AA * BB
            x_2 %= P

            z_2 = E * ((AA + ((Curve25519.a24 * E) % P)) % P)
            z_2 %= P

        x_2, x_3 = X25519Base._const_time_swap(x_2, x_3, swap)
        z_2, z_3 = X25519Base._const_time_swap(z_2, z_3, swap)

        return (x_2 * Curve25519.mod_mult_inv(z_2)) % P

    @staticmethod
    def _point_double(pt_n: UZProjectivePoint):
        """Double point, assuming projective coords. Based on https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3."""
        P = Curve25519.p

        u, z = pt_n
        uu = pow(u, 2, P)
        zz = pow(z, 2, P)
        u_res = (uu - zz) ** 2
        uz = u * z
        z_res = 4 * uz * (uu + Curve25519.A * uz + zz)
        return u_res % P, z_res % P

    @staticmethod
    def _uz_point_diff_add(pt_n: UZProjectivePoint, pt_m: UZProjectivePoint, pt_diff: UZProjectivePoint):
        """Add the points, given their diff, assuming projective coords.
        Based on https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3,
        and the formulae in Martin's tutorial."""
        P = Curve25519.p

        u_n, z_n = pt_n
        u_m, z_m = pt_m
        u_d, z_d = pt_diff
        u = (z_d << 2) * pow((u_m * u_n - z_m * z_n), 2, P)
        z = (u_d << 2) * pow((u_m * z_n - z_m * u_n), 2, P)
        return u % P, z % P

    @staticmethod
    def _compute_x25519_double_and_add(k_str: DecodeInput, u_str: DecodeInput) -> str:
        """Compute value of x25519. Source: RFC.

        Args:
            k_str (str): scalar argument
            u_str (str): u coordinate

        Returns:
            str: result encoded as hex string
        """
        k = X25519Base._decode_scalar(k_str)
        u = X25519Base._decode_u_coordinate(u_str)

        P = Curve25519.p

        zero: UZProjectivePoint = (1, 0)
        one: UZProjectivePoint = (u, 1)
        m_p, m_1_p = zero, one

        for t in reversed(range(X25519Base.BITS + 1)):
            bit = bool(k & (1 << t))
            m_p, m_1_p = X25519Base._const_time_swap(m_p, m_1_p, bit)
            m_p, m_1_p = X25519Base._point_double(m_p), X25519Base._uz_point_diff_add(m_p, m_1_p, one)
            m_p, m_1_p = X25519Base._const_time_swap(m_p, m_1_p, bit)

        x, z = m_p
        inv_z = Curve25519.mod_mult_inv(z)
        res = (x * inv_z) % P
        return X25519Base._encode_u_coordinate(res, to_str=True)

    @abc.abstractmethod
    def __init__(self) -> None:
        """Abstract init"""
