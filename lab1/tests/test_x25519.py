import json
from pathlib import Path

import pytest
from nacl.utils import random
from src.lab1.x25519 import X25519


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
    x = X25519(sk)
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
    x = X25519(sk_1)
    y = X25519(sk_2)

    assert x.compute_shared_secret(y.public) == exp
    assert y.compute_shared_secret(x.public) == exp


@pytest.mark.parametrize(
    "sk_1,sk_2",
    [(random(32).hex(), random(32).hex()) for _ in range(100)],
)
def test_shared_secret_randomised(sk_1: str, sk_2: str):
    x = X25519(sk_1)
    y = X25519(sk_2)

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

    x = X25519(private)
    assert x.compute_shared_secret(public) == shared
