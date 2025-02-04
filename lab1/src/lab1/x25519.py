"""Client for X25519 diffie-Hellman implementation"""

from nacl.utils import random

from .x25519_base import DecodeSizeError, X25519Base


class X25519Client(X25519Base):
    """Concrete client-facing implementation of Diffie-Hellman using Curve25519"""

    type Key = str
    BASE_POINT_U = "09" + 31 * "00"

    _private: Key
    _public: Key

    def __init__(self, secret: str | None = None) -> None:
        """Initialise from secret hex string, or if None using pynacl"""
        if secret is None:
            self._private = random(self.ALLOWED_LEN).hex()
            try:
                self._decode_scalar(self._private)
            except DecodeSizeError as e:
                raise e
        else:
            self._private = secret

        # derive public key
        self._public = self._compute_x25519_ladder(self._private, self.BASE_POINT_U)

    @property
    def public(self):
        """Getter for public key"""
        return self._public

    def compute_shared_secret(self, other_pk: Key):
        """Compute shared secret from other's public key"""
        shared_secret = self._compute_x25519_ladder(self._private, other_pk)
        return shared_secret
