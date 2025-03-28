"""Ed25519 user-facing implementation"""

from secrets import token_bytes as random_bytes

from .ed25519_base import BadKeyLengthError, Ed25519Base


class Ed25519Client(Ed25519Base):
    """Concrete client-facing implementation of Ed25519"""

    _secret: bytes
    _public: bytes

    type ClientInput = bytes | str

    def __init__(self, secret: ClientInput | None = None) -> None:
        """Initialise client from some randomly generated secret key, or generate one"""
        if secret:
            self._secret = self._clean_input(secret)
            if (secret_len := len(self._secret)) != self.KEY_LEN:
                raise BadKeyLengthError(self.KEY_LEN, secret_len)
        else:
            self._secret = random_bytes(self.KEY_LEN)

        self._public = self._secret_to_public(self._secret)

    @staticmethod
    def _clean_input(data: ClientInput) -> bytes:
        return bytes.fromhex(data) if isinstance(data, str) else data

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
