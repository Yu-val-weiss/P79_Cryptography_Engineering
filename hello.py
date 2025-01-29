from hashlib import sha256  # Python standard library

from lab1 import hello as hello1
from lab2 import hello as hello2
from lab3 import hello as hello3


def main():
    print("Hello from p79-cryptography-engineering!")
    print(sha256(hello1().encode("utf-8")).hexdigest())
    print(sha256(hello2().encode("utf-8")).hexdigest())
    print(sha256(hello3().encode("utf-8")).hexdigest())


if __name__ == "__main__":
    main()
