"""Runners for lab1"""

from src.lab1.x25519 import X25519

if __name__ == "__main__":
    x = X25519()
    scalar = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    print(x._decode_scalar(scalar))
    # print(bytes.fromhex(scalar).decode(encoding="ascii"))
    # print(bytes([ord(b) for b in scalar]).decode())
    # print(len(scalar))
    # y = x._decode_scalar()
    # print(y)
    # b = int(31029842492115040904895560451863089656472772604678260265531221036453811406496).to_bytes(
    #     length=32, byteorder="big", signed=False
    # )

    # print(b.hex())

    # decoded = x._decode_u_coordinate(
    #     bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    # )
    # print(decoded)
    # print(
    #     x._decodeLittleEndian(
    #         int(34426434033919594451155107781188821651316167215306631574996226621102155684838).to_bytes(
    #             length=32
    #         )
    #     )
    # )
    # print(repr(x._encode_u_coordinate(decoded)))
