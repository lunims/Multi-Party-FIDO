import timeit

from fido2.server import Fido2Server
from fido2.client import Fido2Client, WindowsClient, UserInteraction, _Ctap2ClientAssertionSelection
from fido2.hid import CtapHidDevice

from fido2.ctap2.base import AttestationResponse, AssertionResponse

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend



from threshold_rsa.threshold_rsa import Threshold_RSA, KeyShare, SignShare
from authenticators.authenticator import Authenticator
from authenticators.threshold_rsa_authenticator import Threshold_RSA_Authenticator, pkcs1_5_pad

import hashlib

NUMBER_OF_ITERATIONS = 10

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
t = Threshold_RSA()

def key_gen_rsa():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )

def bench_key_gen_rsa():
    print("BENCH KEY GEN RSA")
    execution_time = timeit.timeit(key_gen_rsa, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")

def threshold_deal_two_party():
    t = Threshold_RSA()
    return t.deal(2, 2, [key.private_numbers().p, key.private_numbers().q], key.public_key().public_numbers().e)

def bench_two_party_deal():
    print("BENCH TWO PARTY DEAL")
    execution_time = timeit.timeit(threshold_deal_two_party, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")

key_shares = t.deal(2, 2, [key.private_numbers().p, key.private_numbers().q], key.public_key().public_numbers().e)
byte_msg = "BENCHMARK_SIGN".encode('utf-8')
sign_shares = []
hasher = hashlib.sha256()
hasher.update(byte_msg)
hashed_msg= hasher.digest()
padded_hash = pkcs1_5_pad(hashed_msg, 2048)

for i in range(2):
    sign_shares.append(key_shares[i].sign(key.public_key().public_numbers(), padded_hash))


def combine():
    return t.combine_sign_shares(key.public_key().public_numbers(), sign_shares, padded_hash)

def bench_combine_sign_shares():
    print("BENCH COMBINE SIGN SHARES")
    execution_time = timeit.timeit(combine, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")


def sign_share():
    hasher = hashlib.sha256()
    hasher.update(byte_msg)
    hashed_msg= hasher.digest()
    padded_hash = pkcs1_5_pad(hashed_msg, 2048)
    return key_shares[0].sign(key.public_key().public_numbers(), padded_hash)

def bench_generate_sign_share():
    print("BENCH GENERATE SIGN SHARE")
    execution_time = timeit.timeit(sign_share, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")

def sign_rsa():
    return key.sign(
        byte_msg,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def bench_standard_rsa_signing():
    print("BENCH STANDARD RSA SIGNING")
    execution_time = timeit.timeit(sign_rsa, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")

shares = t.deal(2, 2, [key.private_numbers().p, key.private_numbers().q], key.public_key().public_numbers().e)

uv = "discouraged"
server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}
create_options, state = server.register_begin(
    user, user_verification=uv, authenticator_attachment="cross-platform"
)
authenticators =[]
for s in shares:
    authenticators.append(Threshold_RSA_Authenticator(s, key.public_key(), 1903, "https://example.com", benchmark= True))

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
    

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)

credentials = [auth_data.credential_data]

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

result = []
sign_shares = []
# Authenticate the credential


i = 1
for j in range(2):
    response = authenticators[j].get_assertion(request_options["publicKey"])
    result.append(response)
    sign_shares.append(SignShare(int.from_bytes(response._assertions[0].signature, "big"), i, 2, 2))
    i += 1
auth_data = result[0]._assertions[0].auth_data
client_data_hash = result[0]._client_data.hash
concat = auth_data + client_data_hash

hasher = hashlib.sha256()
hasher.update(concat)
concat_hashed = hasher.digest()
        
padded_hash = pkcs1_5_pad(concat_hashed, 2048)

bench_key_gen_rsa()
bench_two_party_deal()
bench_generate_sign_share()
bench_standard_rsa_signing()
bench_combine_sign_shares()



shares = t.deal(2, 2, [key.private_numbers().p, key.private_numbers().q], key.public_key().public_numbers().e)

uv = "discouraged"
server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}
create_options, state = server.register_begin(
    user, user_verification=uv, authenticator_attachment="cross-platform"
)
authenticators = []
for s in shares:
    authenticators.append(Threshold_RSA_Authenticator(s, key.public_key(), 1903, "https://example.com", benchmark= True))

user = {"id": b"user_id", "name": "A. User"}

uv = 'discouraged'

def cred():
    # Prepare parameters for makeCredential
    create_options, state = server.register_begin(
        user, user_verification=uv, authenticator_attachment="cross-platform"
    )
    for a in authenticators:
        try:
            result = a.make_credential(create_options["publicKey"])
        except: 
            abort = True
    auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
    )

def bench_t_cred():
    print("BENCH T CRED")
    execution_time = timeit.timeit(cred, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")

bench_t_cred()



def do_assertion():
    return authenticators[0].get_assertion(request_options["publicKey"])

def bench_get_assertion():
    print("BENCH GET ASSERTION")
    execution_time = timeit.timeit(do_assertion, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")


bench_get_assertion()


def full_assertion():
    result = []
    sign_shares = []
    i = 1
    for j in range(200):
        response = authenticators[j].get_assertion(request_options["publicKey"])
        result.append(response)
        sign_shares.append(SignShare(int.from_bytes(response._assertions[0].signature, "big"), i, 300, 200))
        i += 1
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
    server.authenticate_complete(
        state,
        credentials,
        resp.credential_id,
        resp.client_data,
        resp.authenticator_data,
        resp.signature,
    )    


def bench_get_full_assertion():
    print("BENCH GET FULL ASSERTION")
    execution_time = timeit.timeit(full_assertion, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")



shares = t.deal(2, 2, [key.private_numbers().p, key.private_numbers().q], key.public_key().public_numbers().e)

uv = "discouraged"
server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}
create_options, state = server.register_begin(
    user, user_verification=uv, authenticator_attachment="cross-platform"
)
user = {"id": b"user_id", "name": "A. User"}

uv = 'discouraged'

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user, user_verification=uv, authenticator_attachment="cross-platform"
)


result = None
abort = False
authenticator = Authenticator(1903, "https://example.com")

def credential_register():
    result = authenticator.make_credential(create_options['publicKey'])

    # Complete registration
    auth_data = server.register_complete(
        state, result.client_data, result.attestation_object
    )


def bench_std_cred():
    print("BENCH STD CRED")
    execution_time = timeit.timeit(credential_register, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")

bench_std_cred()

    
result = authenticator.make_credential(create_options['publicKey'])

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]

def std_auth():
# Prepare parameters for getAssertion
    request_options, state = server.authenticate_begin(credentials, user_verification=uv)

    resp = authenticator.get_assertion(request_options['publicKey'])
    result = resp.get_response(0)
    server.authenticate_complete(
        state,
        credentials,
        result.credential_id,
        result.client_data,
        result.authenticator_data,
        result.signature,
    )

def bench_std_assertion():
    print("BENCH STD ASSERTION:")
    execution_time = timeit.timeit(std_auth, 
        number=NUMBER_OF_ITERATIONS)
    average_exec_time = (execution_time / NUMBER_OF_ITERATIONS) * 1000
    print("Total Execution Time: " + str(execution_time * 1000))
    print("Average Execution Time: " + str(average_exec_time))
    print("")

