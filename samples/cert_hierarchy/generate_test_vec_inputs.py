#!/usr/bin/python3

from cbor2 import dumps, load
import binascii

x5chain_map_label = 33

# Encode CRED_I and ID_CRED_I
with open('initiator/initiator_device_cert.der', 'rb') as ifp:
    initiator_cert_raw = ifp.read()

#print("initiator_cert_raw: ", binascii.b2a_hex(initiator_cert_raw), "\n")

cred_i = dumps(initiator_cert_raw)

print("cred_i size", len(cred_i))
print("cred_i:", binascii.b2a_hex(cred_i), "\n")

id_cred_i = dumps({x5chain_map_label: initiator_cert_raw})

print("id_cred_i size", len(id_cred_i))
print("id_cred_i:", binascii.b2a_hex(id_cred_i), "\n")


# Encode CRED_R and ID_CRED_R
with open('responder/responder_device_cert.der', 'rb') as rfp:
    responder_cert_raw = rfp.read()

#print("responder_cert_raw: ", binascii.b2a_hex(responder_cert_raw), "\n")

cred_r = dumps(responder_cert_raw)

print("cred_r size", len(cred_r))
print("cred_r ", binascii.b2a_hex(cred_r), "\n")

id_cred_r = dumps({x5chain_map_label: responder_cert_raw})

print("id_cred_r size", len(id_cred_r))
print("id_cred_r:", binascii.b2a_hex(id_cred_r), "\n")
