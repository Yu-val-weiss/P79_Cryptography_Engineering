"""Test Lab 0"""

import pytest

from src.lab0.digest import Digest, DigestAlgorithm


def test_blake2b_default_length():
    digest = Digest(algorithm=DigestAlgorithm.BLAKE2B, output_len_bits=64)
    data = b"test data"
    result = digest.digest(data)
    assert len(result) == 8
    assert result.hex() == "eab94977a17791d0"


def test_init_checks_for_too_large_output_length():
    # A good API should not allow output lengths that exceed the
    # digest's output length and catch this as early as possible.

    # Blake2b is limited to 512 bits (64 bytes)
    Digest(algorithm=DigestAlgorithm.BLAKE2B, output_len_bits=512)
    with pytest.raises(AssertionError):
        Digest(algorithm=DigestAlgorithm.BLAKE2B, output_len_bits=512 + 8)

    # SHA256 is limited to 256 bits (32 bytes)
    Digest(algorithm=DigestAlgorithm.SHA256, output_len_bits=256)
    with pytest.raises(AssertionError):
        Digest(algorithm=DigestAlgorithm.SHA256, output_len_bits=256 + 8)


def test_sha256_default_length():
    digest = Digest(algorithm=DigestAlgorithm.SHA256)
    data = b"test data"
    result = digest.digest(data)
    assert len(result) == 32
    assert result.hex() == "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"


def test_sha256_custom_length():
    digest = Digest(algorithm=DigestAlgorithm.SHA256, output_len_bits=128)
    data = b"test data"
    result = digest.digest(data)
    assert len(result) == 16
    assert result.hex() == "916f0027a575074ce72a331777c3478d"
