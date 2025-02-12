"""Client for X25519 diffie-Hellman implementation"""

from secrets import token_bytes as random

from .errors import DecodeSizeError, ZeroSharedSecret
from .x25519_base import X25519Base


class X25519Client(X25519Base):
    """Concrete client-facing implementation of Diffie-Hellman using Curve25519"""

    type Key = str
    BASE_POINT_U = "09" + 31 * "00"

    _private: int
    _public: int
    _public_hex_str: Key

    def __init__(self, secret: str | bytes | list[int] | None = None) -> None:
        """Initialise from secret hex string or bytes or list[int], or if None use secure random"""
        if secret is None:
            secret = random(self.ALLOWED_LEN)
        try:
            self._private = self._decode_scalar(secret)
        except DecodeSizeError as e:
            raise e

        base_point_u = self._decode_u_coordinate(self.BASE_POINT_U)

        # derive public key
        self._public = self._compute_x25519_ladder(self._private, base_point_u)
        self._public_hex_str = self._encode_u_coordinate(self._public)

    @property
    def public(self) -> Key:
        """Getter for public key"""
        return self._public_hex_str

    def compute_shared_secret(self, other_pk: Key, *, abort_if_zero: bool = False):
        """Compute shared secret from other's public key"""
        shared_secret = self._compute_x25519_ladder(self._private, other_pk)
        if abort_if_zero and shared_secret == 0:
            raise ZeroSharedSecret("Shared secret was 0, aborting!")
        return shared_secret
