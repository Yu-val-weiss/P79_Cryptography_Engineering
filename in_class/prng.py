import math

# def rng_next(state=11):
#     new_state = state * 12345678987654321
#     next_rand = new_state * 420029
#     return new_state & 0xFF, next_rand & 0xFF


# def rng_next(state=11):
#     new_state = state + 4
#     next_rand = state + state + (5 << state & 0xF)
#     return new_state & 0xFFFF, next_rand & 0xFF


def rng_next(state=11):
    new_state = state * 17**3
    next_rand = new_state // 0x21
    return new_state & 0xFFFF, next_rand & 0xFF


# def rng_next(state=11):
#     new_state = state * 0x343FD + 0x269EC3
#     next_rand = new_state >> 0x10
#     return new_state & 0xFFFF, next_rand & 0xFF


# def rng_next(state=11):
#     new_state = state * 12345678 + 1234567
#     next_rand = new_state ^ 1337133
#     return new_state & 0xFF, next_rand & 0xFF


if __name__ == "__main__":
    state, rand = rng_next()
    samples = [rand]
    for _ in range(10000):
        state, rand = rng_next(state)
        samples.append(rand)

    # Calculate histogram
    histogram = [0] * 256
    for sample in samples:
        histogram[sample] += 1

    # Calculate entropy
    entropy = 0.0
    for count in histogram:
        if count:
            p = count / len(samples)
            entropy -= p * math.log2(p)

    print(entropy)
