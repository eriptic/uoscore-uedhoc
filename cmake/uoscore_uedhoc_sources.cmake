# SPDX-License-Identifier: Apache-2.0 OR MIT

# Single source of truth for the library's own source files.
#
# Included by the top-level CMakeLists.txt (standalone build) and by
# zephyr/CMakeLists.txt (Zephyr module). Every new .c file in src/ must be
# added here; cmake/check_source_list.cmake fails if one is missing.
#
# Defines (all paths absolute):
#   UOSCORE_UEDHOC_ROOT            repository root
#   UOSCORE_UEDHOC_INCLUDE_DIR     public include directory
#   UOSCORE_UEDHOC_COMMON_SOURCES  code shared by OSCORE and EDHOC
#   UOSCORE_SOURCES                OSCORE
#   UEDHOC_SOURCES                 EDHOC

get_filename_component(UOSCORE_UEDHOC_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(UOSCORE_UEDHOC_INCLUDE_DIR "${UOSCORE_UEDHOC_ROOT}/inc")

set(UOSCORE_UEDHOC_COMMON_SOURCES
  src/common/byte_array.c
  src/common/crypto_p256.c
  src/common/crypto_wrapper.c
  src/common/memcpy_s.c
  src/common/print_util.c
)

set(UOSCORE_SOURCES
  src/oscore/aad.c
  src/oscore/coap2oscore.c
  src/oscore/nonce.c
  src/oscore/nvm.c
  src/oscore/option.c
  src/oscore/oscore2coap.c
  src/oscore/oscore_coap.c
  src/oscore/oscore_cose.c
  src/oscore/oscore_hkdf_info.c
  src/oscore/oscore_interactions.c
  src/oscore/replay_protection.c
  src/oscore/security_context.c
  src/cbor/oscore_aad_array.c
  src/cbor/oscore_enc_structure.c
  src/cbor/oscore_info.c
)

set(UEDHOC_SOURCES
  src/edhoc/associated_data_encode.c
  src/edhoc/bstr_encode_decode.c
  src/edhoc/cert.c
  src/edhoc/ciphertext.c
  src/edhoc/edhoc_cose.c
  src/edhoc/edhoc_exporter.c
  src/edhoc/edhoc_method_type.c
  src/edhoc/hkdf_info.c
  src/edhoc/initiator.c
  src/edhoc/int_encode_decode.c
  src/edhoc/okm.c
  src/edhoc/plaintext_decode.c
  src/edhoc/plaintext_encode.c
  src/edhoc/prk.c
  src/edhoc/responder.c
  src/edhoc/retrieve_cred.c
  src/edhoc/runtime_context.c
  src/edhoc/signature_or_mac_msg.c
  src/edhoc/suites.c
  src/edhoc/th.c
  src/cbor/edhoc_decode_bstr_type.c
  src/cbor/edhoc_decode_cert.c
  src/cbor/edhoc_decode_id_cred_x.c
  src/cbor/edhoc_decode_int_type.c
  src/cbor/edhoc_decode_message_1.c
  src/cbor/edhoc_decode_message_2.c
  src/cbor/edhoc_decode_message_3.c
  src/cbor/edhoc_decode_plaintext2.c
  src/cbor/edhoc_decode_plaintext3.c
  src/cbor/edhoc_encode_bstr_type.c
  src/cbor/edhoc_encode_data_2.c
  src/cbor/edhoc_encode_enc_structure.c
  src/cbor/edhoc_encode_id_cred_x.c
  src/cbor/edhoc_encode_info.c
  src/cbor/edhoc_encode_int_type.c
  src/cbor/edhoc_encode_message_1.c
  src/cbor/edhoc_encode_message_2.c
  src/cbor/edhoc_encode_message_3.c
  src/cbor/edhoc_encode_message_error.c
  src/cbor/edhoc_encode_sig_structure.c
  src/cbor/edhoc_encode_th2.c
)

list(TRANSFORM UOSCORE_UEDHOC_COMMON_SOURCES PREPEND "${UOSCORE_UEDHOC_ROOT}/")
list(TRANSFORM UOSCORE_SOURCES PREPEND "${UOSCORE_UEDHOC_ROOT}/")
list(TRANSFORM UEDHOC_SOURCES PREPEND "${UOSCORE_UEDHOC_ROOT}/")
