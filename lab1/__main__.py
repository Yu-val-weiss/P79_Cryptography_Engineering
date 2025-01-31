"""Runners for lab1"""

from src.lab1.x25519_base import X25519Base

if __name__ == "__main__":
    k = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    u = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"

    X25519Base._compute_x25519_ladder(k, u)
