from pathlib import Path

import pytest
from src.lab1.ed25519_base import Ed25519Base


def read_test_file():
    # Get the current script directory
    script_dir = Path(__file__).parent

    # Define the relative path to the file you want to open
    file_path = script_dir / "ed25519_test.txt"

    # Open the file
    with open(file_path, "r") as file:
        for line in file:
            sk, pk, msg, sig, *_ = line.split(":")
            yield sk, pk, msg, sig


def mess_string(s, pos, change):
    return s[:pos] + int.to_bytes(s[pos] ^ change, 1, "little") + s[pos + 1 :]


@pytest.mark.parametrize("sk,pk,msg,sig", read_test_file())
def test_all_from_big_file(sk: str, pk: str, msg: str, sig: str):
    secret = bytes.fromhex(sk)[:32]
    public = bytes.fromhex(pk)
    message = bytes.fromhex(msg)
    signature = bytes.fromhex(sig)[:64]

    assert Ed25519Base._secret_to_public(secret) == public
    assert Ed25519Base._sign(secret, message) == signature
    assert Ed25519Base._verify(public, message, signature)

    # assert Ed25519Base._secret_to_public(secret) == public
    # assert Ed25519Base._sign(secret, message) == signature
    # assert Ed25519Base._verify(public, message, signature)
