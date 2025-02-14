import json
from itertools import chain
from pathlib import Path

import pytest
from nacl.utils import random
from src.lab1.errors import DecodeSizeError, ZeroSharedSecret
from src.lab1.invalidation import CallLimiter
from src.lab1.x25519 import X25519Client


@pytest.mark.parametrize(
    "sk,exp_pk",
    [
        (
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        ),
        (
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ),
    ],
)
def test_pk_generation(sk: str, exp_pk: str):
    x = X25519Client(sk)
    assert x.public == exp_pk


@pytest.mark.parametrize(
    "sk_1,sk_2,exp",
    [
        (
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        ),
    ],
)
def test_shared_secret(sk_1: str, sk_2: str, exp: str):
    x = X25519Client(sk_1)
    y = X25519Client(sk_2)

    x_shared = x.compute_shared_secret(y.public)
    y_shared = y.compute_shared_secret(x.public)

    assert x._encode_u_coordinate(x_shared, to_str=True) == exp
    assert y._encode_u_coordinate(y_shared, to_str=True) == exp


@pytest.mark.parametrize(
    "sk_1,sk_2",
    [(random(32).hex(), random(32).hex()) for _ in range(100)],
)
def test_shared_secret_randomised(sk_1: str, sk_2: str):
    x = X25519Client(sk_1)
    y = X25519Client(sk_2)

    assert x.compute_shared_secret(y.public) == y.compute_shared_secret(x.public)


def load_wycheproof_data():
    # Get the current script directory
    script_dir = Path(__file__).parent

    # Define the relative path to the file you want to open
    file_path = script_dir / "x25519_test.json"

    # Open the file
    with open(file_path, "r") as file:
        j = json.load(file)

    return [(t["private"], t["public"], t["shared"]) for t in j["testGroups"][0]["tests"]]


@pytest.mark.parametrize(
    "private,public,shared",
    load_wycheproof_data(),
)
def test_wycheproof(private: str, public: str, shared: str):
    """Source for these tests: https://github.com/C2SP/wycheproof/blob/master/testvectors/x25519_test.json."""

    x = X25519Client(private)
    with CallLimiter.disable_call_limit(x.compute_shared_secret):
        shared_secret = x.compute_shared_secret(public)

        assert X25519Client._encode_u_coordinate(shared_secret, to_str=True) == shared

        if shared == "00" * 32:
            with pytest.raises(ZeroSharedSecret):
                x.compute_shared_secret(public, abort_if_zero=True)


@pytest.mark.parametrize("private", ["ab" * i for i in chain(range(32), range(33, 50))])
def test_size_error(private: str):
    with pytest.raises(DecodeSizeError):
        _ = X25519Client(private)


@pytest.mark.parametrize(
    "private",
    [
        "00" * 32,
        "ff" * 32,
    ],
)
def test_edge_cases(private: str):
    _ = X25519Client(private)
