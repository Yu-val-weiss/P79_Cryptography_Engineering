"""Defines a dataclass containing core constants for the curve"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Curve25519:
    """Holds constants related to Curve25519"""

    # prime p
    p = 2**255 - 19

    # curve constant
    d = 37095705934669439343138083508754565189542113879843219016388785533085940283555

    # group order
    q = 2**252 + 27742317777372353535851937790883648493

    # curve parameter A in v^2 = u^3 + A*u^2 + u
    A = 486662

    # constant defined in RFC7748
    a24 = 121665

    @staticmethod
    def mod_mult_inv(x: int) -> int:
        """Calculate the modular multiplicative inverse"""
        return pow(x, Curve25519.p - 2, Curve25519.p)
