from random import randint
from secrets import token_bytes as random_bytes

import pytest
from src.lab1.ed25519_base import Ed25519Point
from src.lab1.errors import DecompressionError


def random_points_generator(num: int):
    i = 0
    while i < num:
        x = Ed25519Point.decompress(random_bytes())
        if x:
            yield x
            i += 1


@pytest.mark.parametrize("pt", random_points_generator(50))
def test_scalar_equals_add(pt: Ed25519Point):
    mul = randint(2, 10)
    assert mul * pt == sum([pt for _ in range(mul - 1)], start=pt)


@pytest.mark.parametrize("pt", random_points_generator(50))
def test_double_equals_add(pt: Ed25519Point):
    assert pt.double() == pt + pt


def test_invalid_decompress():
    with pytest.raises(DecompressionError):
        Ed25519Point.decompress(random_bytes(50))
