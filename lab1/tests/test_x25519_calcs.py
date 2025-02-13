"""Lab 1 testing"""

import pytest
from src.lab1.x25519_base import X25519Base
from tqdm import tqdm


@pytest.mark.parametrize(
    "k_str,u_str,expected",
    [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ],
)
def test_compute_ladder(k_str: str, u_str: str, expected: str):
    k = X25519Base._decode_scalar(k_str)
    u = X25519Base._decode_u_coordinate(u_str)
    res = X25519Base._compute_x25519_ladder(k, u)

    assert X25519Base._encode_u_coordinate(res, to_str=True) == expected


@pytest.mark.parametrize(
    "k,u,expected",
    [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ],
)
def test_compute_double_and_add(k: str, u: str, expected: str):
    assert X25519Base._compute_x25519_double_and_add(k, u) == expected


@pytest.mark.parametrize(
    "iters,expected",
    [
        (1, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
        (1_000, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
        (1_000_000, "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"),  # ~ 20min runtime
    ],
)
def test_iterated_compute_ladder(iters: int, expected: str):
    k = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
    u = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")

    for _ in tqdm(range(iters)):
        old_k = k
        res = X25519Base._compute_x25519_ladder(k, u)
        k = X25519Base._encode_u_coordinate(res, to_str=False)
        u = old_k

    assert k.hex() == expected
