"""Ed25519 user-facing implementation"""

from .ed25519_base import BadKeyLengthError, Ed25519Base


class Ed25519Client(Ed25519Base):
    """Concrete client-facing implementation of Ed25519"""

    _secret: bytes
    _public: bytes

    type ClientInput = bytes | str

    def __init__(self, secret: ClientInput) -> None:
        """Initialise client from secret"""
        self._secret = self._clean_input(secret)
        if (lens := len(self._secret)) != self.ALLOWED_LEN:
            raise BadKeyLengthError(self.ALLOWED_LEN, lens)

        self._public = self._secret_to_public(self._secret)

    @staticmethod
    def _clean_input(data: ClientInput) -> bytes:
        if isinstance(data, str):
            return bytes.fromhex(data)
        return data

    @property
    def public(self):
        """Public key"""
        return self._public

    def sign(self, msg: ClientInput) -> bytes:
        """Sign message from either bytes or hex string"""
        return self._sign(self._secret, self._clean_input(msg))

    def verify(self, public: ClientInput, msg: ClientInput, signature: ClientInput) -> bool:
        """Verify a message's signature"""
        return self._verify(
            self._clean_input(public),
            self._clean_input(msg),
            self._clean_input(signature),
        )
