"""Implementation for X25519's base class."""

import abc

type Point = tuple[int, int]


class X25519Base(abc.ABC):
    """Implements X25519"""

    BITS = 255
    ALLOWED_LEN = 32
    p = 2**255 - 19
    A = 486662
    a24 = 121665

    @staticmethod
    def _decode_little_endian(b: bytes | list[int]):
        """Decodes a list of bytes (little-endian) into an int."""
        return sum([b[i] << 8 * i for i in range(X25519Base.ALLOWED_LEN)])

    @staticmethod
    def _decode_u_coordinate(u: str) -> int:
        """Decode string representation of coordinate."""
        u_list = X25519Base._string_to_bytes(u)
        u_list[-1] &= (1 << (X25519Base.BITS % 8)) - 1
        return X25519Base._decode_little_endian(u_list)

    @staticmethod
    def _encode_u_coordinate(u: int) -> str:
        """Encodes u coordinate into byte string."""
        u = u % X25519Base.p
        x = u.to_bytes(length=X25519Base.ALLOWED_LEN, byteorder="little")
        return bytes(x).hex()

    @staticmethod
    def _decode_scalar(k: str):
        """Decodes a scalar hex string into a little endian int"""
        k_list = X25519Base._string_to_bytes(k)
        k_list[0] &= 248
        k_list[31] &= 127
        k_list[31] |= 64
        return X25519Base._decode_little_endian(k_list)

    @staticmethod
    def _string_to_bytes(k: str) -> list[int]:
        """Decodes a hex string into a list of ints (list of bytes)."""
        bs = bytes.fromhex(k)
        if len(bs) != 32:
            raise ValueError("Values for Curve25519 must be 32 bytes")
        return [b for b in bs]

    @staticmethod
    def _const_time_swap[T](a: T, b: T, swap: int) -> tuple[T, T]:
        """Swap two values in constant time. Source: https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3."""
        index = int(swap) * 2
        temp = (a, b, b, a)
        return temp[index : index + 2]  # type: ignore

    @staticmethod
    def _compute_x25519_ladder(k_str: str, u_str: str) -> str:
        """Compute value of x25519. Source: RFC.

        Args:
            k_str (str): scalar argument
            u_str (str): u coordinate

        Returns:
            str: result encoded as hex string
        """
        k = X25519Base._decode_scalar(k_str)
        u = X25519Base._decode_u_coordinate(u_str)

        P = X25519Base.p

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

            z_2 = E * ((AA + ((X25519Base.a24 * E) % P)) % P)
            z_2 %= P

        x_2, x_3 = X25519Base._const_time_swap(x_2, x_3, swap)
        z_2, z_3 = X25519Base._const_time_swap(z_2, z_3, swap)

        result = (x_2 * (pow(z_2, P - 2, P))) % P

        return X25519Base._encode_u_coordinate(result)

    @staticmethod
    def _point_double(pt_n: Point):
        """Double point, assuming projective coords. Based on https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3."""
        P = X25519Base.p

        x, z = pt_n
        xx = x**2
        zz = z**2
        x_res = (xx - zz) ** 2
        xz = x * z
        z_res = 4 * xz * (xx + X25519Base.A * xz + zz)
        return x_res % P, z_res % P

    @staticmethod
    def _point_add(pt_n: Point, pt_m: Point, pt_diff: Point):
        """Add the points, given their diff, assuming projective coords.
        Based on https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3,
        and the formulae in Martin's tutorial."""
        P = X25519Base.p

        x_n, z_n = pt_n
        x_m, z_m = pt_m
        x_d, z_d = pt_diff
        x = (z_d << 2) * (x_m * x_n - z_m * z_n) ** 2
        z = (x_d << 2) * (x_m * z_n - z_m * x_n) ** 2
        return x % P, z % P

    @staticmethod
    def _compute_x25519_double_and_add(k_str: str, u_str: str) -> str:
        """Compute value of x25519. Source: RFC.

        Args:
            k_str (str): scalar argument
            u_str (str): u coordinate

        Returns:
            str: result encoded as hex string
        """
        k = X25519Base._decode_scalar(k_str)
        u = X25519Base._decode_u_coordinate(u_str)

        P = X25519Base.p

        zero: Point = (1, 0)
        one: Point = (u, 1)
        m_p, m_1_p = zero, one

        for t in reversed(range(X25519Base.BITS + 1)):
            bit = bool(k & (1 << t))
            m_p, m_1_p = X25519Base._const_time_swap(m_p, m_1_p, bit)
            m_p, m_1_p = X25519Base._point_double(m_p), X25519Base._point_add(m_p, m_1_p, one)
            m_p, m_1_p = X25519Base._const_time_swap(m_p, m_1_p, bit)

        x, z = m_p
        inv_z = pow(z, P - 2, P)
        res = (x * inv_z) % P
        return X25519Base._encode_u_coordinate(res)

    @abc.abstractmethod
    def __init__(self) -> None:
        """Abstract init"""
