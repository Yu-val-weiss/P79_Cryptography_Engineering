"""Ed25519 user-facing implementation"""

from .ed25519_base import BadKeyLengthError, Ed25519Base


class Ed25519Client(Ed25519Base):
    """Concrete client-facing implementation of Ed25519"""

    _secret: bytes
    _public: bytes

    def __init__(self, secret: bytes | str) -> None:
        """Initialise client from secret"""
        super().__init__()
        if isinstance(secret, str):
            self._secret = bytes.fromhex(secret)
        else:
            self._secret = secret
        if len(self._secret) != self.ALLOWED_LEN:
            raise BadKeyLengthError("Invalid secret length")

        self._public = self._secret_to_public(self._secret)

    @property
    def public(self):
        """Public key getter"""
        return self._public

    def sign(self, msg: bytes) -> bytes:
        """Sign message"""
        return self._sign(self._secret, msg)

    def verify(self, public: bytes, msg: bytes, signature: bytes) -> bool:
        """Verify a message's signature"""
        return self._verify(public, msg, signature)
