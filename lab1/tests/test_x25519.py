"""Lab 1 testing"""

import pytest
from src.lab1.x25519 import X25519


@pytest.mark.parametrize(
    "k,expected",
    [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            31029842492115040904895560451863089656472772604678260265531221036453811406496,
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            35156891815674817266734212754503633747128614016119564763269015315466259359304,
        ),
    ],
)
def test_decode_scalar(k, expected):
    assert X25519._decode_scalar(k) == expected


@pytest.mark.parametrize(
    "u,expected",
    [
        (
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            34426434033919594451155107781188821651316167215306631574996226621102155684838,
        ),
        (
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            8883857351183929894090759386610649319417338800022198945255395922347792736741,
        ),
    ],
)
def test_decode_u_coordinate(u, expected):
    assert X25519._decode_u_coordinate(u) == expected
