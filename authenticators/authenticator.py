from threshold_rsa.threshold_rsa import KeyShare
from fido2.ctap2.base import AttestationResponse, AssertionResponse
from fido2.client import WebAuthnClient, AssertionSelection, _BaseClient, _Ctap2ClientAssertionSelection
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
    AttestationConveyancePreference,
    AuthenticatorData,
    AttestedCredentialData
)

from fido2.ctap2.pin import ClientPin, PinProtocol

from fido2.cose import RS256

from fido2.rpid import verify_rp_id
from fido2.ctap import CtapDevice, CtapError

from threading import Event
from typing import Mapping, Dict, Any, List, Optional, Callable


import hashlib
import random


from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


import logging

logger = logging.getLogger(__name__)


import secrets

def pkcs1_5_pad(hash: bytes, key_length: int) -> bytes:
        hash_length = len(hash)

        # DER-encoded prefix for SHA-256
        sha256_prefix = bytes([
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00, 0x04, 0x20
        ])

        prefix_length = len(sha256_prefix)
        padded_length = key_length // 8
        ps_length = padded_length - 3 - hash_length - prefix_length

        if ps_length < 8:
            raise ValueError('Key size is too small for the given hash length')

        # Create the padded array
        padded = bytearray(padded_length)
        padded[0] = 0x00
        padded[1] = 0x01
        padded[2:2 + ps_length] = b'\xFF' * ps_length
        padded[2 + ps_length] = 0x00

        # Copy the prefix and the hash after the padding
        padded[3 + ps_length:3 + ps_length + prefix_length] = sha256_prefix
        padded[3 + ps_length + prefix_length:] = hash

        return bytes(padded)

    


class Authenticator(WebAuthnClient, _BaseClient):

    def __init__(
        self, 
        random_seed: int, 
        origin: str,
        verify: Callable[[str, str], bool] = verify_rp_id,
    ):
        super().__init__(origin, verify)
        self.threshold = False
        self.signature_counter = 0
        self.identifier = b'\x18\x04\x19\x03\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77'
        self.random = random.Random()
        self.random.seed(random_seed)

    def generate_credential_id(self) -> None:
        """

        Wrapper for credential_id generation. All authenticators need to have the same random seed.

        """
        self.credential_id = self.random.randbytes(16)

    def user_presence_check(self):
        inp = input("Enter 'y' to confirm: ")
        if inp != 'y':
            raise ValueError

    def make_credential(
        self,
        options: PublicKeyCredentialCreationOptions,
        event: Optional[Event] = None,
    ) -> AuthenticatorAttestationResponse:
        """

        Creates a credential. 
        - via Fido2Client in https://github.com/Yubico/python-fido2/blob/main/fido2/client.py

        :param options: PublicKeyCredentialCreationOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.

        """

        options = PublicKeyCredentialCreationOptions.from_dict(options)
        event = event or Event()
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()

        rp = options.rp
        if rp.id is None:
            url = urlparse(self.origin)
            if url.scheme != "https" or not url.netloc:
                raise ClientError.ERR.BAD_REQUEST(
                    "RP ID required for non-https origin."
                )
            rp = replace(rp, id=url.netloc)

        logger.debug(f"Register a new credential for RP ID: {rp.id}")
        self._verify_rp_id(rp.id)

        client_data = self._build_client_data(
            CollectedClientData.TYPE.CREATE, options.challenge
        )

        selection = options.authenticator_selection or AuthenticatorSelectionCriteria()
        enterprise_attestation = None
        if options.attestation == AttestationConveyancePreference.ENTERPRISE:
            if self.info.options.get("ep"):
                if self._enterprise_rpid_list is not None:
                    # Platform facilitated
                    if rp.id in self._enterprise_rpid_list:
                        enterprise_attestation = 2
                else:
                    # Vendor facilitated
                    enterprise_attestation = 1

        try:
            return self.do_make_credential(
                client_data,
                rp,
                options.user,
                options.pub_key_cred_params,
                options.exclude_credentials,
                options.extensions,
                selection.require_resident_key,
                selection.user_verification,
                enterprise_attestation,
                event,
            )
        except CtapError as e:
            raise _ctap2client_err(e)
        finally:
            if options.timeout:
                timer.cancel()

    def do_make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        exclude_list,
        extensions,
        rk,
        user_verification,
        enterprise_attestation,
        event,
    ) -> AuthenticatorAssertionResponse:
        """

        Generates a credential and sends back Attestation response with encoded public key.

        :param client_data
        :param rp
        :param user
        :param key_params
        :param exclude_list
        :param extensions
        :param rk
        :param user_verification
        :param enterprise_attestation
        :param event

        """

        hasher = hashlib.sha256()
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
        cose_public_key = RS256.from_cryptography_key(self.key.public_key())
        self.generate_credential_id()
        attested_credential_data = AttestedCredentialData.create(self.identifier, self.credential_id, cose_public_key)
        bytes_rp_id = rp.id.encode('utf-8')
        hasher.update(bytes_rp_id)
        rp_id_hash = hasher.digest()
        authenticator_data = AuthenticatorData.create(rp_id_hash, AuthenticatorData.FLAG.AT | AuthenticatorData.FLAG.UP, 0, attested_credential_data)
        empty_att_stmt: Mapping[str, Any] = {}
        extension_outputs = {}
        return AuthenticatorAttestationResponse(
            client_data,
            AttestationObject.create("none", authenticator_data, empty_att_stmt),
            extension_outputs,
        )



    def get_assertion(
        self,
        options: PublicKeyCredentialRequestOptions,
        event: Optional[Event] = None,
    ) -> AssertionSelection:
        """Get an assertion.

        :param options: PublicKeyCredentialRequestOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialRequestOptions.from_dict(options)
        event = event or Event()
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()

        logger.debug(f"Assert a credential for RP ID: {options.rp_id}")
        self._verify_rp_id(options.rp_id)

        client_data = self._build_client_data(
            CollectedClientData.TYPE.GET, options.challenge
        )

        try:
            return self.do_get_assertion(
                client_data,
                options.rp_id,
                options.allow_credentials,
                options.extensions,
                options.user_verification,
                event,
            )
        except CtapError as e:
            raise _ctap2client_err(e)
        finally:
            if options.timeout:
                timer.cancel()

    def do_get_assertion(
        self,
        client_data,
        rp_id,
        allow_list,
        extensions,
        user_verification,
        event,
    ):

        hasher = hashlib.sha256()
        bytes_rp_id = rp_id.encode("utf-8")
        hasher.update(bytes_rp_id)
        rp_id_hash = hasher.digest()
        # Process extensions
        client_inputs = extensions or {}
        extension_inputs = {}
        used_extensions = []
        permissions = ClientPin.PERMISSION(0)
        self.signature_counter += 1
        authenticator_data = AuthenticatorData.create(rp_id_hash, AuthenticatorData.FLAG.UP, counter= 0)
        #self.user_presence_check()
        concat = authenticator_data + client_data.hash
        signature = self.key.sign(concat,
                                padding.PKCS1v15(),
                                hashes.SHA256())

        credential = {"type": "public-key", "id": self.credential_id}

        assertion = AssertionResponse(credential, authenticator_data, signature)

        return _Ctap2ClientAssertionSelection(
            client_data,
            [assertion],
            used_extensions,
            None,
            None,
        )

