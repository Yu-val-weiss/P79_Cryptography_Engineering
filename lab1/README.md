# Lab 1 - Primitives, Diffie-Hellman, Signatures

## Code structure

```text
.
├── src/lab1             
│   ├── ed25519_base.py             # Base class for ed25519, containing calculation primitives; curve point arithmetic 
│   ├── ed25519.py                  # User-facing API class for ed25519, wrapping the calculations into a clean class
│   ├── errors.py                   # Various error/exception classes
│   ├── x25519_base.py              # Defines the base class for X25519 (i.e. Curve25519), containing all the calculation primitives
│   └── x25519.py                   # User-facing API class for X25519 (Diffie-Hellman on Curve 25519)
├── tests                           
│   ├── test_ed25519_calcs.py       # test suite for ed25519 calculation primitives
│   ├── test_ed25519.py             # test suite for user-facing ed25519 class
│   ├── test_epoint.py              # test suite for curve point arithmetic
│   ├── test_x_primitives.py        # test suite for x25519 primitives such as encoding/decoding
│   ├── test_x_5519_calcs.py        # test suite for curve25519 calculation primitives
│   └── tests_x25519.py             # test suite for user-facing x25519 (diffie-hellman) class
├── .dockerignore                   # specifies what files the Docker container should ignore
├── Dockerfile                      # specifies Docker container for running tests
└── run.sh                          # script to build and run Dockerfile
```
