from math import factorial



def mod_inverse(a: int, b: int) -> int:
    """

    Calculates the modular inverse of given parameters.

    :param a: int
    :param b: int

    """

    m0 = b
    x0, x1 = 0, 1

    if b == 1:
        return 0

    while a > 1:
        q = a // b
        t = b
        b = a % b
        a = t
        t = x0
        x0 = x1 - q * x0
        x1 = t

    if x1 < 0:
        x1 += m0

    return x1

def mod_pow(base: int, exp: int, mod: int) -> int:
    """

    Own implementation with added check for negative exponents.

    :param base: int 
    :param exp: int 
    :param mod: int

    """

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
    """ 
    
    Computes lagrange Interpolation for the shares. Needed in combine_sign_shares().

    :param delta: int -> ∆ = l!
    :param S: [] -> arrray of sign_shares
    :param i: int -> 0
    :param j: int -> index of share
    
    """

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



def compute_polynomial(k: int, a: [], x: int, m: int) -> int:
    """ 
    
    Computes Polynomial according to the paper for Key Share Generation. Used in deal() function.
    
    :param k: int -> threshold
    :param a: [] -> array with a[0] = d and rest random numbers within range (0, m-1)
    :param x: int -> index
    :param m: int -> m = p'q' = (p - 1)(q - 1)/4

    """
    sum = 0
    for i in range(k):
        xi = x ** i
        prod = (a[i] * xi) % m
        sum += prod
    return sum % m


def calculate_delta(l: int) -> int:
    """ 
    
    Wrapper for factorial computation. Calculates delta.
    -> ∆ = l!

    :param l: int -> number of players
    
    """

    return factorial(l)
