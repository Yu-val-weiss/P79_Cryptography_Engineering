from secrets import token_bytes as random

import pytest
from src.lab1.ed25519_base import Ed25519Point
from src.lab1.errors import DecompressionError


def random_points_generator(num: int):
    i = 0
    while i < num:
        x = Ed25519Point.decompress(random())
        if x:
            yield x
            i += 1


@pytest.mark.parametrize("pt", random_points_generator(50))
def test_scalar_equals_add(pt: Ed25519Point):
    assert 3 * pt == pt + pt + pt
    assert 7 * pt == pt + pt + pt + pt + pt + pt + pt


def test_invalid_decompress():
    with pytest.raises(DecompressionError):
        Ed25519Point.decompress(random(50))
