from enum import Enum

from nacl import encoding, hash

#
# This project contains an implementation of a Digest class with some
# missing functionality. Use the provided Docker container to run the tests
# and see what's currently broken.
#

# Default output length in bits
DEFAULT_OUTPUT_LEN_BITS = 256


class DigestAlgorithm(Enum):
    SHA256 = "sha256"
    BLAKE2B = "blake2b"


class Digest:
    """Class to compute the truncated hash of data"""

    def __init__(
        self,
        algorithm: DigestAlgorithm,
        output_len_bits: int = DEFAULT_OUTPUT_LEN_BITS,
    ):
        """
        Initializes the Digest class.

        :param output_len_bits: The output length in bits
        :param algorithm: The algorithm to use (see `DigestAlgorithm`)
        """
        assert output_len_bits > 0
        assert output_len_bits % 8 == 0
        self.output_len_bytes = output_len_bits // 8

        if algorithm == DigestAlgorithm.SHA256:
            assert output_len_bits <= 256
        elif algorithm == DigestAlgorithm.BLAKE2B:
            assert self.output_len_bytes <= hash.BLAKE2B_BYTES_MAX

        self.algorithm = algorithm

    def truncate(self, data: bytes) -> bytes:
        """Truncate data to correct length

        Args:
            data (bytes): Data to truncate

        Returns:
            bytes: Truncated output
        """
        if len(data) <= self.output_len_bytes:
            return data
        else:
            return data[: self.output_len_bytes]

    def digest(
        self,
        data: bytes,
    ) -> bytes:
        """
        Computes a diggest of the data using the specified algorithm.
        The result is truncated to the specified output length.

        :param data: The data to compute the digest of
        :return: The truncated digest of the data
        """
        if self.algorithm == DigestAlgorithm.SHA256:
            # TODO: fix the following lines first
            h = hash.sha256(
                message=data,
                encoder=encoding.RawEncoder,
            )
            return self.truncate(h)
        elif self.algorithm == DigestAlgorithm.BLAKE2B:
            h = hash.blake2b(
                data=data,
                encoder=encoding.RawEncoder,
            )
            return self.truncate(h)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
