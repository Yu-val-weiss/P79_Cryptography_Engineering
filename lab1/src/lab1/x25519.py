"""Implementation for X25519."""


class X25519:
    """Implements X25519"""

    BITS = 255
    ALLOWED_LEN = 32
    p = 2**255 - 19

    @staticmethod
    def _decode_little_endian(b: bytes | list[int]):
        """Decodes a list of bytes (little-endian) into an int."""
        return sum([b[i] << 8 * i for i in range(X25519.ALLOWED_LEN)])

    @staticmethod
    def _decode_u_coordinate(u: str) -> int:
        """Decode string representation of coordinate."""
        u_list = X25519._string_to_bytes(u)
        # Ignore any unused bits.
        if X25519.BITS % 8:
            u_list[-1] &= (1 << (X25519.BITS % 8)) - 1
        return X25519._decode_little_endian(u_list)

    @staticmethod
    def _encode_u_coordinate(u: int) -> str:
        """Encodes u coordinate into byte string."""
        u = u % X25519.p
        return "".join([chr((u >> 8 * i) & 0xFF) for i in range(X25519.ALLOWED_LEN)])

    @staticmethod
    def _decode_scalar(k: str):
        """Decodes a scalar hex string into a little endian int"""
        k_list = X25519._string_to_bytes(k)
        k_list[0] &= 248
        k_list[31] &= 127
        k_list[31] |= 64
        return X25519._decode_little_endian(k_list)

    @staticmethod
    def _string_to_bytes(k: str) -> list[int]:
        """Decodes a hex string into a list of ints (list of bytes)."""
        bs = bytes.fromhex(k)
        if len(bs) != 32:
            raise ValueError("Values for Curve25519 must be 32 bytes")
        return [b for b in bs]

    def encrypt(self, k: str, u: str):
        """Encrypt

        Args:
            k (str): _description_
            u (str): _description_

        Raises:
            NotImplementedError: _description_
        """
        raise NotImplementedError()
