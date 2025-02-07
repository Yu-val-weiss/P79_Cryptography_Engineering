"""Define all errors/exceptions"""


class BadLengthError(ValueError):
    """Base class for bad lengths, should override message_base"""

    message_base = ""
    unit = "bytes"

    def __init__(self, exp_len: int, got_len: int) -> None:
        """Initialise base bad length class"""
        if self.unit != "":
            self.unit = " " + self.unit
        msg = f"{self.message_base}, expected {exp_len}{self.unit} but got {got_len}"
        super().__init__(msg)


class DecompressionError(BadLengthError):
    """Point decompression error"""

    message_base = "Error decompressing"


class BadKeyLengthError(BadLengthError):
    """Key expansion error"""

    message_base = "Bad key length"


class BadSignatureLengthError(BadLengthError):
    """Signature expansion error"""

    message_base = "Bad signature length"


class DecodeSizeError(BadLengthError):
    """Invalid scalar/u-coordinate size exception"""

    message_base = "Invalid scalar/u-coordinate"
