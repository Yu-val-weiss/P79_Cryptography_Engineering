def rng_next(state=11):
    new_state = state * 12345678987654321
    next_rand = new_state * 420029
    return new_state & 0xFF, next_rand & 0xFF


if __name__ == "__main__":
    state, rand = rng_next()
    for i in range(100):
        state, rand = rng_next(state)
        print(rand)
