import random
from math import gcd
from sympy import gcdex
from threshold_rsa.util import mod_inverse, mod_pow, calculate_delta, compute_lambda, compute_polynomial
from cryptography.hazmat.primitives.asymmetric import rsa

"""

This implementation of "Practical Threshold Signatures" by shoup is based on following GO repository: https://github.com/katzenpost/circl/tree/main/tss/rsa.
However there are still some changes to the original code snippets.

"""


class SignShare:
    """
    
    Sign Share on a specified message. Generated by KeyShare.sign() in rsa_authenticator
    
    """


    def __init__(self, xi: int, index: int, players: int, threshold: int) -> None:
        self.xi = xi
        self.index = index
        self.players = players
        self.threshold = threshold



class KeyShare:
    """

    Class which represents a key share generated by the deal() function.
    This key share is used by the rsa_authenticator to generate its part of the signature.

    """

    def __init__(self, players: int, threshold: int, si: int, index: int) -> None:
        self.players = players
        self.threshold = threshold
        self.si = si
        self.index = index
        self.twoDeltaSi = None

    def get2DeltaSi(self) -> int:
        """

        Calculates two delta si: 2Δs_i: delta * 2 
        Needed for generating a sign share.

        """

        delta = calculate_delta(self.players)
        self.twoDeltaSi = delta * 2 * self.si
        return self.twoDeltaSi

    def sign(self, pub: rsa.RSAPublicNumbers, digest: bytes) -> SignShare:
        """ 
        
        Generates the corresponding sign share on a message.
        -> x^{2∆s_i}

        :param pub: rsa.RSAPublicNumbers -> public numbers n and e of RSA key
        :param digest: bytes -> digest to sign 
        
        """

        x = int.from_bytes(digest, "big")
        exp = self.get2DeltaSi()
        
        signShare = SignShare(
            xi=0,
            index=self.index,
            players=self.players,
            threshold=self.threshold
        )

        signShare.xi = pow(x, exp, pub.n)
        return signShare


class Threshold_RSA:
    
    def deal(self, players: int, threshold: int, primes: [], e: int) -> []:
        """

        Takes a RSA Key and splits it with corresponding parameters into multiple key shares.
        - according to Shoup's "Practical Threshold signatures"
        - https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf

        :param players: int -> overall value of players participating
        :param threshold: int -> threshold which is needed for full signature
        :param primes: [p, q] -> primes of previously generated RSA key
        :param e: int -> public exponent of previously generated RSA key

        p' = (p - 1) / 2
        q' = (q - 1) / 2
        m = (p - 1)(q - 1)
        m = (p - 1)(q - 1) / 4
        """

        if len(primes) != 2:
            raise ValueError("Multiprime RSA keys are unsupported")

        p = primes[0]
        q = primes[1]

        pprime = p - 1
        m = q - 1
        m = m * pprime
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

    def combine_sign_shares(self, pub: rsa.RSAPublicNumbers, shares: [], msg: bytes) -> int:
        """
        
        Takes generated sign shares and message in order to create the full signature.
        - according to Shoup's "Practical Threshold signatures"
        - https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf

        :param pub: rsa.RSAPublicNumbers -> public numbers n and e
        :param shares: [] -> Array of generated sign shares by rsa_authenticators
        :param msg: bytes -> message which was used for generating the sign shares
        
        """

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