import pytest
from src.lab1.errors import DecodeSizeError
from src.lab1.x25519_base import X25519Base, XZProjectivePoint


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


def pad_hex_to_32(s):
    # pad little-endian 0s to the end
    return s + (32 * 2 - len(s)) * "0"


@pytest.mark.parametrize(
    "k,kmod",
    [(hex(x)[2:], pad_hex_to_32(hex(x % X25519Base.p)[2:])) for x in range(2**255 - 19, 2**255)],
)
def test_decode_non_canonical_scalars(k: str, kmod: str):
    # non canonical scalars must not error, and must be treated as if they had already been modded
    # (despite not being modded) so should not be the same as actually modded values
    res = X25519Base._decode_scalar(k)
    res_mod = X25519Base._decode_scalar(kmod)
    assert res != res_mod


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
            # but just allows testing this function properly
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
    with pytest.raises(DecodeSizeError):
        X25519Base._string_to_bytes("ab" * 16)  # Too short (16 bytes)
    with pytest.raises(DecodeSizeError):
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
    "u_str,expected",
    [
        (
            "e6dbffffffffffffffffffff24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            (
                7756732024156241206238486735774659135229984142939217379667394471774585196906,
                7463005382528956391873957755075029590495786025252121505558497905489036877786,
            ),
        ),
        (
            "e6db0000000000000000000024b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            (
                47185822988732343473230504836451583833317770425818672469097814643599931236292,
                54008436692679323643674401823761841525101513045091595709436249466215063753209,
            ),
        ),
        (
            "a" * 62 + "00",
            (
                1888571844392181660463534842494344521215147896037676107264247085236095504131,
                37076336792061828986943314430358264598399768149397652855630322308573080590189,
            ),
        ),
        (
            "b" * 62 + "00",
            (
                12692266840175292460224661589420799245652482606890270934074529423123495613156,
                22754807516552177179102461213402548644019616006141737446067818720277054041185,
            ),
        ),
        (
            "1" * 62 + "00",
            (
                45479112173155112757717930016931089710144464093817300847703836508402841394749,
                6372283172261436681140814833094166894949426028786616989096461517663390555060,
            ),
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaa24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            (
                7695569184386171180157976511778272759590870705378968297980721247909416393364,
                55446532382649108204487755508081681218231393181046124990286630133924508267422,
            ),
        ),
        (
            "eeeeeeeeeeeeeeeeeeeeeeee24b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            (
                34104032686348813617430241344372506175168582557105305258608195516444242472299,
                23492189406939945773518379661451353348319926620514861393401110204570138870712,
            ),
        ),
        (
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            (
                10812997290877953414876713771559096076988124789286094484808612862248751257640,
                17057780096276725197266926689719741321978387205345998857384484874814072643392,
            ),
        ),
        (
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413",
            (
                47451832282885890372032707302823060701970186277101926852746420938449755064985,
                10328088739839721428383282422192839696410837632536656510784664642694549694636,
            ),
        ),
    ],
)
def test_double(u_str: str, expected: XZProjectivePoint):
    u = X25519Base._decode_u_coordinate(u_str)
    u_p: XZProjectivePoint = (u, 1)
    doubled = X25519Base._point_double(u_p)
    assert doubled == expected
