# provide here your tool chain
#CC = gcc
#AR = ar
#CC = /opt/gcc-arm-none-eabi-9-2020-q2-update/bin/arm-none-eabi-gcc
#AR = /opt/gcc-arm-none-eabi-9-2020-q2-update/bin/arm-none-eabi-ar
#CC = clang-13

#architecture
#ARCH = -m32

# the library is compiled with the folowing optimization 
OPT = -O3

# Uncomment this to print intermediery results at runtime
#DEBUG_PRINT += -DDEBUG_PRINT


# CBOR engine
# currently only ZCBOR is supported
CBOR_ENGINE += -DZCBOR

# The uoscore-uedhoc can be used with different crypto angines. 
# The user can provide as well additinal cryptoengines by providing 
# implementations of the function defined (as week) in the crypto_wrapper file.
# Curretnly we have build in support for the following engines which 
# allow fowing modes of operation and suites:
#
# EDHOC suites: 
# Value: 0
#    Array: 10, -16, 8, 4, -8, 10, -16
#    Desc: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA,
#          AES-CCM-16-64-128, SHA-256

#    Value: 1
#    Array: 30, -16, 16, 4, -8, 10, -16
#    Desc: AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA,
#          AES-CCM-16-64-128, SHA-256

#    Value: 2
#    Array: 10, -16, 8, 1, -7, 10, -16
#    Desc: AES-CCM-16-64-128, SHA-256, 8, P-256, ES256,
#          AES-CCM-16-64-128, SHA-256

#    Value: 3
#    Array: 30, -16, 16, 1, -7, 10, -16
#    Desc: AES-CCM-16-128-128, SHA-256, 16, P-256, ES256,
#          AES-CCM-16-64-128, SHA-256

#    Value: 4
#    Array: 24, -16, 16, 4, -8, 24, -16
#    Desc: ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA,
#          ChaCha20/Poly1305, SHA-256


# EDHOC methods: 
# +-------+-------------------+-------------------+-------------------+
# | Value | Initiator         | Responder         | Reference         |
# +-------+-------------------+-------------------+-------------------+
# |     0 | Signature Key     | Signature Key     | [[this document]] |
# |     1 | Signature Key     | Static DH Key     | [[this document]] |
# |     2 | Static DH Key     | Signature Key     | [[this document]] |
# |     3 | Static DH Key     | Static DH Key     | [[this document]] |
# +-------+-------------------+-------------------+-------------------+
#
#
#
# +--------+---------+---------+-------------------------------------------
# protocol | suite   | method  | ENGINE
# +--------+---------+---------+-------------------------------------------
# | OSCORE |         |         | TINYCRYPT or MBEDTLS
# | EDHOC  | 0/1     | 0/1/2   | COMPACT25519 with (TINYCRYPT or MBEDTLS)
# | EDHOC  | 0/1     | 3       | MBEDTLS or (COMPACT25519 with TINYCRYPT)
# | EDHOC  | 2/3     | 0/1/2/3 | MBEDTLS
# | EDHOC  | 0/1/2/3 | 0/1/2/3 | MBEDTLS and COMPACT25519


#CRYPTO_ENGINE += -DTINYCRYPT
CRYPTO_ENGINE += -DCOMPACT25519
CRYPTO_ENGINE += -DMBEDTLS