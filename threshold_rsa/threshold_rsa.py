import random
from math import gcd
from sympy import gcdex
from threshold_rsa.util import mod_inverse, mod_pow, calculate_delta, compute_lambda, compute_polynomial


class KeyShare:
    def __init__(self, players, threshold, si, index):
        self.players = players
        self.threshold = threshold
        self.si = si
        self.index = index
        self.twoDeltaSi = None

    def get2DeltaSi(self):
        delta = calculate_delta(self.players)
        # 2Δs_i: delta * 2
        self.twoDeltaSi = delta * 2 * self.si
        return self.twoDeltaSi

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
        signShare.xi = pow(x, exp, pub.n)
        return signShare

class SignShare:
    def __init__(self, xi, index, players, threshold):
        self.xi = xi
        self.index = index
        self.players = players
        self.threshold = threshold


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
            ai = random.randint(0, m - 1)
            a.append(ai)

        shares = []
        for i in range(1, players + 1):
            si = compute_polynomial(threshold, a, i, m)
            share = KeyShare(players, threshold, si, i)
            share.get2DeltaSi()
            shares.append(share)

        return shares

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
        delta = calculate_delta(players)
        n = pub.n
        
        for share in shares:
            lambda_ = compute_lambda(delta, shares, 0, share.index)

            exp = lambda_ * 2
            abs_exp = abs(exp)
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