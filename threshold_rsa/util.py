from math import factorial



def mod_inverse(a: int, m: int) -> int:
    m0 = m
    x0, x1 = 0, 1

    if m == 1:
        return 0

    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = x0
        x0 = x1 - q * x0
        x1 = t

    if x1 < 0:
        x1 += m0

    return x1

def mod_pow(base: int, exp: int, mod: int) -> int:
    if exp < 0:
        base = mod_inverse(base, mod)
        exp = -exp
    result = 1
    power = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * power) % mod
        power = (power * power) % mod
        exp //= 2
    return result

def compute_lambda(delta: int, S: [], i: int, j: int) -> int:
    if i == j:
        raise ValueError("rsa_threshold: i and j can't be equal by precondition")

    foundi = False
    foundj = False

    num = 1
    den = 1

    for k in range(len(S)):
        s = S[k]
        jprime = s.index
        if jprime == j:
            foundj = True
            continue
        if jprime == i:
            foundi = True
            break
        num *= i - jprime
        den *= j - jprime

    lambda_ = delta * num // den

    if foundi:
        raise ValueError(f"rsa_threshold: i: {i} should not be in S")

    if not foundj:
        raise ValueError(f"rsa_threshold: j: {j} should be in S")

    return lambda_



def compute_polynomial(k: int, a: int, x: int, m: int) -> int:
    sum = 0
    for i in range(k):
        xi = x ** i
        prod = (a[i] * xi) % m
        sum += prod
    return sum % m


def calculate_delta(l: int) -> int:
    # ∆ = l!
    return factorial(l)
