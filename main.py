from fido2.server import Fido2Server
from fido2.client import Fido2Client, WindowsClient, UserInteraction, _Ctap2ClientAssertionSelection
from fido2.hid import CtapHidDevice

from fido2.ctap2.base import AttestationResponse, AssertionResponse


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend



from threshold_rsa.threshold_rsa import Threshold_RSA, KeyShare, SignShare
from authenticators.threshold_rsa_authenticator import Threshold_RSA_Authenticator, pkcs1_5_pad


import hashlib

import argparse

from demo import two_party_demo, threshold_demo



def main():
    parser = argparse.ArgumentParser(description= "Protecting FIDO Credentials using Multi and Threshold Signatures")

    subparsers = parser.add_subparsers(dest='command', required=True, help='Choose one of the following commands')

    # Arguments for demo
    parser_a = subparsers.add_parser('demo', help='Demo of a FIDO authentication')
    parser_a.add_argument('threshold', type=int, help='Input for Threshold')
    parser_a.add_argument('players', type=int, help='Input for participating players')

    args = parser.parse_args()

    if args.command == 'demo':
        if args.threshold == 2 and args.players == 2:
            two_party_demo()
        else:
            threshold_demo(args.threshold, args.players)




if __name__ == "__main__":
    main()