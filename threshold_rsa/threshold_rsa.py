from math import factorial
import random
from math import gcd
from sympy import gcdex

def mod_inverse(a, m):
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

class KeyShare:
    def __init__(self, players, threshold, si, index):
        self.players = players
        self.threshold = threshold
        self.si = si
        self.index = index
        self.twoDeltaSi = None

    def get2DeltaSi(self):
        delta = calculateDelta(self.players)
        # 2Δs_i: delta * 2
        self.twoDeltaSi = delta * 2 * self.si
        return self.twoDeltaSi

    def expo(self, value, exponent, modulo):
        return pow(value, exponent, modulo)

    def sign(self, pub, digest):
        x = int.from_bytes(digest, "big")
        exp = self.get2DeltaSi()
        
        signShare = SignShare(
            xi=0,
            index=self.index,
            players=self.players,
            threshold=self.threshold
        )

        # x^{2∆s_i}
        signShare.xi = self.expo(x, exp, pub.n)
        return signShare

class SignShare:
    def __init__(self, xi, index, players, threshold):
        self.xi = xi
        self.index = index
        self.players = players
        self.threshold = threshold


def mod_pow(base, exp, mod):
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

def computeLambda(delta, S, i, j):
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


def calculateDelta(l):
    # ∆ = l!
    return factorial(l)

class Threshold_RSA:
    
    def deal(self, players, threshold, primes, e):
        ONE = 1
        #primes = keyComponents['primes']
        #e = keyComponents['e']

        if len(primes) != 2:
            raise ValueError("Multiprime RSA keys are unsupported")

        p = primes[0]
        q = primes[1]

        # p' = (p - 1) / 2
        pprime = p - ONE


        # q' = (q - 1) / 2
        m = q - ONE

        # m = (p - 1)(q - 1)
        m = m * pprime

        # m = (p - 1)(q - 1) / 4
        m = m >> 2

        d = mod_inverse(e, m)
        if d is None:
            raise ValueError("rsa_threshold: no ModInverse for e in Z/Zm")

        a = [d]
        for i in range(1, threshold):
            ai = self.random_bigint(0, m - 1)
            a.append(ai)

        shares = []
        for i in range(1, players + 1):
            si = self.compute_polynomial(threshold, a, i, m)
            share = KeyShare(players, threshold, si, i)
            share.get2DeltaSi()
            shares.append(share)

        return shares

    def compute_polynomial(self, k, a, x, m):
        sum = 0
        for i in range(k):
            xi = x ** i
            prod = (a[i] * xi) % m
            sum += prod
        return sum % m

    def random_bigint(self, min_val, max_val):
        return random.randint(min_val, max_val)

    def combine_sign_shares(self, pub, shares, msg):
        players = shares[0].players
        threshold = shares[0].threshold

        for share in shares:
            if share.players != players:
                raise ValueError("rsa_threshold: shares didn't have consistent players")
            if share.threshold != threshold:
                raise ValueError("rsa_threshold: shares didn't have consistent threshold")

        if len(shares) < threshold:
            raise ValueError("rsa_threshold: insufficient shares for the threshold")

        w = 1
        delta = calculateDelta(players)
        n = pub.n
        
        for share in shares:
            lambda_ = computeLambda(delta, shares, 0, share.index)

            exp = lambda_ * 2
            abs_exp = abs(exp)
            #tmp = mod_pow(share.xi, exp, n)
            tmp = pow(share.xi, exp, n)
            w = (w * tmp) % n
        eprime = delta * delta * 4
        e = pub.e
        a, b, g = gcdex(eprime, e)
        wa = mod_pow(w, a, n)
        x = int.from_bytes(msg, "big")
        xb = mod_pow(x, b, n)
        y = (wa * xb) % n
        ye = mod_pow(y, e, n)

        if ye != x:
            raise ValueError("rsa: internal error")

        return y