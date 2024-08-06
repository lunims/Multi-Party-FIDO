from fido2.server import Fido2Server
from fido2.client import Fido2Client, WindowsClient, UserInteraction, _Ctap2ClientAssertionSelection
from fido2.hid import CtapHidDevice

from fido2.ctap2.base import AttestationResponse, AssertionResponse


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend



from threshold_rsa.threshold_rsa import Threshold_RSA, KeyShare, SignShare
from authenticators.threshold_rsa_authenticator import Threshold_RSA_Authenticator, pkcs1_5_pad


import hashlib

def two_party_demo() -> None:
    # Generate RSA key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    t = Threshold_RSA()

    # First parameter players -> 2
    # Second parameter threshold -> 2
    shares = t.deal(2, 2, [key.private_numbers().p, key.private_numbers().q], key.public_key().public_numbers().e)

    uv = "discouraged"
    server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
    user = {"id": b"user_id", "name": "A. User"}
    create_options, state = server.register_begin(
        user, user_verification=uv, authenticator_attachment="cross-platform"
    )
    authenticators =[]
    for s in shares:
        authenticators.append(Threshold_RSA_Authenticator(s, key.public_key(), 1903, "https://example.com"))

    user = {"id": b"user_id", "name": "A. User"}

    uv = 'discouraged'

    # Prepare parameters for makeCredential
    create_options, state = server.register_begin(
        user, user_verification=uv, authenticator_attachment="cross-platform"
    )
    
    result = None
    abort = False
    for a in authenticators:
        try:
            result = a.make_credential(create_options["publicKey"])
        except: 
            abort = True
    
    if abort:
        print("Credential creation aborted")
        return

    # Complete registration
    auth_data = server.register_complete(
        state, result.client_data, result.attestation_object
    )


    print("New credential created!")

    print("CLIENT DATA:", result.client_data)
    print("ATTESTATION OBJECT:", result.attestation_object)
    print()
    print("CREDENTIAL DATA:", auth_data.credential_data)
    print("")

    credentials = [auth_data.credential_data]

    # Prepare parameters for getAssertion
    request_options, state = server.authenticate_begin(credentials, user_verification=uv)

    result = []
    sign_shares = []
    # Authenticate the credential
    i = 1
    for j in range(2):
        try:
            response = authenticators[j].get_assertion(request_options["publicKey"])
            result.append(response)
            sign_shares.append(SignShare(int.from_bytes(response._assertions[0].signature, "big"), i, 2, 2))
            i += 1
            print("")
            print("ASSERTION SIGN SHARE FROM AUTHENTICATOR " + str(i) + ":")
            print(response._assertions[0].signature)
            print("")
        except:
            abort = True
    if abort:
        print("Assertion aborted")
        return
    auth_data = result[0]._assertions[0].auth_data
    client_data_hash = result[0]._client_data.hash
    concat = auth_data + client_data_hash

    hasher = hashlib.sha256()
    hasher.update(concat)
    concat_hashed = hasher.digest()
        
    padded_hash = pkcs1_5_pad(concat_hashed, 2048)
    combined_signature = t.combine_sign_shares(key.public_key().public_numbers(), sign_shares, padded_hash)
    assertion = AssertionResponse(result[0]._assertions[0].credential, result[0]._assertions[0].auth_data, combined_signature.to_bytes(256, "big"))
    res = _Ctap2ClientAssertionSelection(
            result[0]._client_data,
            [assertion],
            [],
            None,
            None,
        )
    resp = res.get_response(0)
    # Complete authenticator
    # wrong signature -> would raise Error
    server.authenticate_complete(
        state,
        credentials,
        resp.credential_id,
        resp.client_data,
        resp.authenticator_data,
        resp.signature,
    )

    print("FULL SIGNATURE: ")
    print(combined_signature.to_bytes(256, "big"))

    print("")
    print("AUTHENTICATION SUCCESSFUL")

def threshold_demo(threshold: int, players: int) -> None:
    # Generate RSA key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    t = Threshold_RSA()

    # First parameter players -> 2
    # Second parameter threshold -> 2
    shares = t.deal(players, threshold, [key.private_numbers().p, key.private_numbers().q], key.public_key().public_numbers().e)

    uv = "discouraged"
    server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
    user = {"id": b"user_id", "name": "A. User"}
    create_options, state = server.register_begin(
        user, user_verification=uv, authenticator_attachment="cross-platform"
    )
    authenticators =[]
    for s in shares:
        authenticators.append(Threshold_RSA_Authenticator(s, key.public_key(), 1903, "https://example.com"))

    user = {"id": b"user_id", "name": "A. User"}

    uv = 'discouraged'

    # Prepare parameters for makeCredential
    create_options, state = server.register_begin(
        user, user_verification=uv, authenticator_attachment="cross-platform"
    )
    
    result = None
    abort = False
    for a in authenticators:
        try:
            result = a.make_credential(create_options["publicKey"])
        except: 
            abort = True
    
    if abort:
        print("Credential creation aborted")
        return

    # Complete registration
    auth_data = server.register_complete(
        state, result.client_data, result.attestation_object
    )


    print("New credential created!")

    print("CLIENT DATA:", result.client_data)
    print("ATTESTATION OBJECT:", result.attestation_object)
    print()
    print("CREDENTIAL DATA:", auth_data.credential_data)
    print("")

    credentials = [auth_data.credential_data]

    # Prepare parameters for getAssertion
    request_options, state = server.authenticate_begin(credentials, user_verification=uv)

    result = []
    sign_shares = []
    # Authenticate the credential
    i = 0
    print("THRESHOLD NEEDED FOR SIGNATURE: " + str(threshold))
    for j in range(len(authenticators)):
        if len(sign_shares) == threshold:
            break
        try:
            i += 1
            response = authenticators[j].get_assertion(request_options["publicKey"])
            result.append(response)
            print("")
            print("ASSERTION SIGN SHARE FROM AUTHENTICATOR " + str(i) + ":")
            print(response._assertions[0].signature)
            print("")
            sign_shares.append(SignShare(int.from_bytes(response._assertions[0].signature, "big"), i, players, threshold))
        except:
            abort = True
    if len(result) < threshold:
        print("Credential assertion aborted")
        return
    auth_data = result[0]._assertions[0].auth_data
    client_data_hash = result[0]._client_data.hash
    concat = auth_data + client_data_hash

    hasher = hashlib.sha256()
    hasher.update(concat)
    concat_hashed = hasher.digest()
        
    padded_hash = pkcs1_5_pad(concat_hashed, 2048)
    combined_signature = t.combine_sign_shares(key.public_key().public_numbers(), sign_shares, padded_hash)
    assertion = AssertionResponse(result[0]._assertions[0].credential, result[0]._assertions[0].auth_data, combined_signature.to_bytes(256, "big"))
    res = _Ctap2ClientAssertionSelection(
            result[0]._client_data,
            [assertion],
            [],
            None,
            None,
        )
    resp = res.get_response(0)
    # Complete authenticator
    # wrong signature -> error
    server.authenticate_complete(
        state,
        credentials,
        resp.credential_id,
        resp.client_data,
        resp.authenticator_data,
        resp.signature,
    )


    print("FULL SIGNATURE: ")
    print(combined_signature.to_bytes(256, "big"))

    print("")
    print("AUTHENTICATION SUCCESSFUL")