import pytest
from src.lab1.ed25519 import Ed25519Client
from src.lab1.errors import BadKeyLengthError

from .test_ed25519_calcs import RFC_8032_TEST_VECTORS


@pytest.mark.parametrize("sk,msg,sig", [(x[0], x[2], x[3]) for x in RFC_8032_TEST_VECTORS])
def test_client_sign_with_rfc_vectors(sk: str, msg: str, sig: str):
    signature = bytes.fromhex(sig)

    assert Ed25519Client(sk).sign(msg) == signature


@pytest.mark.parametrize("sk,pk,msg,sig", RFC_8032_TEST_VECTORS)
def test_client_verify_with_rfc_vectors(sk: str, pk: str, msg: str, sig: str):
    assert Ed25519Client(sk).verify(pk, msg, sig)


@pytest.mark.parametrize("sk,pk", [x[:2] for x in RFC_8032_TEST_VECTORS])
def test_client_public_key_gen(sk: str, pk: str):
    public = bytes.fromhex(pk)

    assert Ed25519Client(sk).public == public


@pytest.mark.parametrize("sk", ["ab" * i for i in range(50) if i != 32])
def test_client_initialised_with_bad_key_length(sk: str):
    with pytest.raises(BadKeyLengthError):
        Ed25519Client(sk)
