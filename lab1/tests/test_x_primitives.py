import pytest
from src.lab1.x25519 import X25519Base


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
    assert X25519Base._decode_scalar(k) == expected


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
    assert X25519Base._decode_u_coordinate(u) == expected


@pytest.mark.parametrize(
    "u,expected",
    [
        (
            34426434033919594451155107781188821651316167215306631574996226621102155684838,
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        ),
        (
            8883857351183929894090759386610649319417338800022198945255395922347792736741,
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413",
            # note changed to 13 at the end as highlighted in errata
            # this bit is masked on input so doesn't matter for the other ones
            # but just allows testing a function to work
        ),
    ],
)
def test_encode_u_coordinate(u: int, expected: str):
    assert X25519Base._encode_u_coordinate(u) == expected


@pytest.mark.parametrize(
    "u",
    [
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
    ],
)
def test_decode_little_endian(u):
    bs = bytes.fromhex(u)
    assert X25519Base._decode_little_endian(bs) == int.from_bytes(bs, "little")


def test_decode_invalid_length():
    with pytest.raises(ValueError):
        X25519Base._string_to_bytes("ab" * 16)  # Too short (16 bytes)
    with pytest.raises(ValueError):
        X25519Base._string_to_bytes("ab" * 33)  # Too long (33 bytes)


@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        2**255 - 20,  # Just below p
        2**255 - 19,  # Equal to p
        2**255 - 18,  # Just above p
        34426434033919594451155107781188821651316167215306631574996226621102155684838,
        8883857351183929894090759386610649319417338800022198945255395922347792736741,
    ],
)
def test_encode_decode_roundtrip(value):
    encoded = X25519Base._encode_u_coordinate(value)
    decoded = X25519Base._decode_u_coordinate(encoded)
    assert decoded == value % X25519Base.p


@pytest.mark.parametrize(
    "u",
    [
        "e6dbffffffffffffffffffff24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "e6db0000000000000000000024b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "a" * 62 + "00",  # avoid masking on MSB
        "b" * 62 + "00",
        "1" * 62 + "00",
        "aaaaaaaaaaaaaaaaaaaaaaaa24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "eeeeeeeeeeeeeeeeeeeeeeee24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413",
        # note changed to 13 at the end as highlighted in errata
        # this bit is masked on input so doesn't matter for the other ones
        # but just allows testing a function to work
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ],
)
def test_decode_encode_roundtrip(u: str):
    decoded = X25519Base._decode_u_coordinate(u)
    encoded = X25519Base._encode_u_coordinate(decoded)
    assert encoded == u


def test_cannot_init_x25519base():
    with pytest.raises(TypeError):
        X25519Base()  # type: ignore


@pytest.mark.parametrize(
    "u",
    [
        "e6dbffffffffffffffffffff24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "e6db0000000000000000000024b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "a" * 64,
        "b" * 64,
        "1" * 64,
        "aaaaaaaaaaaaaaaaaaaaaaaa24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "eeeeeeeeeeeeeeeeeeeeeeee24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413",
    ],
)
def test_byte_string_conversion(u: str):
    bs = X25519Base._string_to_bytes(u)
    assert X25519Base._bytes_to_string(bs) == u
