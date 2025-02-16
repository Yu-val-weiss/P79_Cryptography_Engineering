"""Client for X25519 diffie-Hellman implementation"""

from secrets import token_bytes as random_bytes

from .errors import ZeroSharedSecret
from .x25519_base import DecodeInput, X25519Base


class X25519Client(X25519Base):
    """Concrete client-facing implementation of Diffie-Hellman using Curve25519"""

    type Key = str
    BASE_POINT_U = X25519Base._decode_u_coordinate("09" + 31 * "00")

    _private: int
    _public: int
    _public_hex_str: Key

    def __init__(self, secret: DecodeInput | None = None) -> None:
        """Initialise from secret hex string or bytes or list[int], or if None use secure random"""
        if secret is None:
            secret = random_bytes(self.ALLOWED_LEN)
        self._private = self._decode_scalar(secret)

        # derive public key
        self._public = self._compute_x25519_ladder(self._private, self.BASE_POINT_U)
        self._public_hex_str = self._encode_u_coordinate(self._public, to_str=True)

    @property
    def public(self) -> Key:
        """Getter for public key"""
        return self._public_hex_str

    def compute_shared_secret(self, other_pk: Key, *, abort_if_zero: bool = False) -> int:
        """Compute shared secret from other's public key"""
        shared_secret = self._compute_x25519_ladder(self._private, other_pk)
        if abort_if_zero and shared_secret == 0:
            raise ZeroSharedSecret()
        return shared_secret
