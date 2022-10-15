#!/usr/bin/python3

# This script converts the testvectors form a JSON format to C source and header file.

import re
import json
import binascii

in_out_path = "../test_vectors/"
in_file = "edhoc_test_vectors_p256_v16.json"
out_file = "edhoc_test_vectors_p256_v16.h"


HEADER = "/*This is an automatically generated file!*/\n\n"
INCLUDES = '#include "edhoc.h"\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n\n'
STRUCT_DEF = "\n\
struct test_vector {\n\
        const uint8_t *method;\n\
        uint32_t method_len;\n\
        \n\
        const uint8_t *SUITES_I;\n\
        uint32_t SUITES_I_len;\n\
        \n\
        const uint8_t *SUITES_R;\n\
        uint32_t SUITES_R_len;\n\
        \n\
        const uint8_t *x_raw;\n\
        uint32_t x_raw_len;\n\
        \n\
        const uint8_t *g_x_raw;\n\
        uint32_t g_x_raw_len;\n\
        \n\
        const uint8_t *g_x;\n\
        uint32_t g_x_len;\n\
        \n\
        const uint8_t *c_i;\n\
        uint32_t c_i_len;\n\
        \n\
        const uint8_t *ead_1;\n\
        uint32_t ead_1_len;\n\
        \n\
        const uint8_t *message_1;\n\
        uint32_t message_1_len;\n\
        \n\
        const uint8_t *y_raw;\n\
        uint32_t y_raw_len;\n\
        \n\
        const uint8_t *g_y_raw;\n\
        uint32_t g_y_raw_len;\n\
        \n\
        const uint8_t *g_y;\n\
        uint32_t g_y_len;\n\
        \n\
        const uint8_t *g_xy_raw;\n\
        uint32_t g_xy_raw_len;\n\
        \n\
        const uint8_t *salt_raw;\n\
        uint32_t salt_raw_len;\n\
        \n\
        const uint8_t *prk_2e_raw;\n\
        uint32_t prk_2e_raw_len;\n\
        \n\
        const uint8_t *sk_r_raw;\n\
        uint32_t sk_r_raw_len;\n\
        \n\
        const uint8_t *pk_r_raw;\n\
        uint32_t pk_r_raw_len;\n\
        \n\
        const uint8_t *prk_3e2m_raw;\n\
        uint32_t prk_3e2m_raw_len;\n\
        \n\
        const uint8_t *c_r;\n\
        uint32_t c_r_len;\n\
        \n\
        const uint8_t *h_message_1_raw;\n\
        uint32_t h_message_1_raw_len;\n\
        \n\
        const uint8_t *h_message_1;\n\
        uint32_t h_message_1_len;\n\
        \n\
        const uint8_t *input_th_2;\n\
        uint32_t input_th_2_len;\n\
        \n\
        const uint8_t *th_2_raw;\n\
        uint32_t th_2_raw_len;\n\
        \n\
        const uint8_t *th_2;\n\
        uint32_t th_2_len;\n\
        \n\
        const uint8_t *id_cred_r;\n\
        uint32_t id_cred_r_len;\n\
        \n\
        const uint8_t *cred_r;\n\
        uint32_t cred_r_len;\n\
        \n\
        const uint8_t *ead_2;\n\
        uint32_t ead_2_len;\n\
        \n\
        const uint8_t *info_mac_2;\n\
        uint32_t info_mac_2_len;\n\
        \n\
        const uint8_t *mac_2_raw;\n\
        uint32_t mac_2_raw_len;\n\
        \n\
        const uint8_t *mac_2;\n\
        uint32_t mac_2_len;\n\
        \n\
        const uint8_t *m_2;\n\
        uint32_t m_2_len;\n\
        \n\
        const uint8_t *sig_or_mac_2_raw;\n\
        uint32_t sig_or_mac_2_raw_len;\n\
        \n\
        const uint8_t *sig_or_mac_2;\n\
        uint32_t sig_or_mac_2_len;\n\
        \n\
        const uint8_t *plaintext_2;\n\
        uint32_t plaintext_2_len;\n\
        \n\
        const uint8_t *info_keystream_2;\n\
        uint32_t info_keystream_2_len;\n\
        \n\
        const uint8_t *keystream_2_raw;\n\
        uint32_t keystream_2_raw_len;\n\
        \n\
        const uint8_t *ciphertext_2_raw;\n\
        uint32_t ciphertext_2_raw_len;\n\
        \n\
        const uint8_t *ciphertext_2;\n\
        uint32_t ciphertext_2_len;\n\
        \n\
        const uint8_t *message_2;\n\
        uint32_t message_2_len;\n\
        \n\
        const uint8_t *sk_i_raw;\n\
        uint32_t sk_i_raw_len;\n\
        \n\
        const uint8_t *pk_i_raw;\n\
        uint32_t pk_i_raw_len;\n\
        \n\
        const uint8_t *prk_4x3m_raw;\n\
        uint32_t prk_4x3m_raw_len;\n\
        \n\
        const uint8_t *input_TH_3;\n\
        uint32_t input_TH_3_len;\n\
        \n\
        const uint8_t *th_3_raw;\n\
        uint32_t th_3_raw_len;\n\
        \n\
        const uint8_t *th_3;\n\
        uint32_t th_3_len;\n\
        \n\
        const uint8_t *id_cred_i;\n\
        uint32_t id_cred_i_len;\n\
        \n\
        const uint8_t *cred_i;\n\
        uint32_t cred_i_len;\n\
        \n\
        const uint8_t *ead_3;\n\
        uint32_t ead_3_len;\n\
        \n\
        const uint8_t *info_mac_3;\n\
        uint32_t info_mac_3_len;\n\
        \n\
        const uint8_t *mac_3_raw;\n\
        uint32_t mac_3_raw_len;\n\
        \n\
        const uint8_t *mac_3;\n\
        uint32_t mac_3_len;\n\
        \n\
        const uint8_t *m_3;\n\
        uint32_t m_3_len;\n\
        \n\
        const uint8_t *sig_or_mac_3_raw;\n\
        uint32_t sig_or_mac_3_raw_len;\n\
        \n\
        const uint8_t *sig_or_mac_3;\n\
        uint32_t sig_or_mac_3_len;\n\
        \n\
        const uint8_t *p_3;\n\
        uint32_t p_3_len;\n\
        \n\
        const uint8_t *a_3;\n\
        uint32_t a_3_len;\n\
        \n\
        const uint8_t *info_k_3;\n\
        uint32_t info_k_3_len;\n\
        \n\
        const uint8_t *k_3_raw;\n\
        uint32_t k_3_raw_len;\n\
        \n\
        const uint8_t *info_iv_3;\n\
        uint32_t info_iv_3_len;\n\
        \n\
        const uint8_t *iv_3_raw;\n\
        uint32_t iv_3_raw_len;\n\
        \n\
        const uint8_t *ciphertext_3_raw;\n\
        uint32_t ciphertext_3_raw_len;\n\
        \n\
        const uint8_t *ciphertext_3;\n\
        uint32_t ciphertext_3_len;\n\
        \n\
        const uint8_t *message_3;\n\
        uint32_t message_3_len;\n\
        \n\
        const uint8_t *input_th_4;\n\
        uint32_t input_th_4_len;\n\
        \n\
        const uint8_t *th_4_raw;\n\
        uint32_t th_4_raw_len;\n\
        \n\
        const uint8_t *th_4;\n\
        uint32_t th_4_len;\n\
        \n\
        const uint8_t *ead_4;\n\
        uint32_t ead_4_len;\n\
        \n\
        const uint8_t *p_4;\n\
        uint32_t p_4_len;\n\
        \n\
        const uint8_t *a_4;\n\
        uint32_t a_4_len;\n\
        \n\
        const uint8_t *info_k_4;\n\
        uint32_t info_k_4_len;\n\
        \n\
        const uint8_t *k_4_raw;\n\
        uint32_t k_4_raw_len;\n\
        \n\
        const uint8_t *info_iv_4;\n\
        uint32_t info_iv_4_len;\n\
        \n\
        const uint8_t *iv_4_raw;\n\
        uint32_t iv_4_raw_len;\n\
        \n\
        const uint8_t *ciphertext_4_raw;\n\
        uint32_t ciphertext_4_raw_len;\n\
        \n\
        const uint8_t *ciphertext_4;\n\
        uint32_t ciphertext_4_len;\n\
        \n\
        const uint8_t *message_4;\n\
        uint32_t message_4_len;\n\
        \n\
        int32_t *oscore_aead_alg;\n\
        \n\
        int32_t *oscore_hash_alg;\n\
        \n\
        const uint8_t *client_sender_id_raw;\n\
        uint32_t client_sender_id_raw_len;\n\
        \n\
        const uint8_t *server_sender_id_raw;\n\
        uint32_t server_sender_id_raw_len;\n\
        \n\
        const uint8_t *info_oscore_secret;\n\
        uint32_t info_oscore_secret_len;\n\
        \n\
        const uint8_t *oscore_secret_raw;\n\
        uint32_t oscore_secret_raw_len;\n\
        \n\
        const uint8_t *info_oscore_salt;\n\
        uint32_t info_oscore_salt_len;\n\
        \n\
        const uint8_t *oscore_salt_raw;\n\
        uint32_t oscore_salt_raw_len;\n\
        \n\
        const uint8_t *key_update_nonce_raw;\n\
        uint32_t key_update_nonce_raw_len;\n\
        \n\
        const uint8_t *prk_4x3m_key_update_raw;\n\
        uint32_t prk_4x3m_key_update_raw_len;\n\
        \n\
        const uint8_t *oscore_secret_key_update_raw;\n\
        uint32_t oscore_secret_key_update_raw_len;\n\
        \n\
        const uint8_t *oscore_salt_key_update_raw;\n\
        uint32_t oscore_salt_key_update_raw_len;\n\
        \n\
        const uint8_t *ca_r;\n\
        uint32_t ca_r_len;\n\
        \n\
        const uint8_t *ca_i;\n\
        uint32_t ca_i_len;\n\
        \n\
        const uint8_t *ca_r_pk;\n\
        uint32_t ca_r_pk_len;\n\
        \n\
        const uint8_t *ca_i_pk;\n\
        uint32_t ca_i_pk_len;\n\
        \n\
        const uint8_t *i_raw;\n\
        uint32_t i_raw_len;\n\
        \n\
        const uint8_t *g_i_raw;\n\
        uint32_t g_i_raw_len;\n\
        \n\
        const uint8_t *r_raw;\n\
        uint32_t r_raw_len;\n\
        \n\
        const uint8_t *g_r_raw;\n\
        uint32_t g_r_raw_len;\n\
        \n\
        const uint8_t *c_i_raw;\n\
        uint32_t c_i_raw_len;\n\
        int32_t *c_i_raw_int;\n\
        \n\
        const uint8_t *c_r_raw;\n\
        uint32_t c_r_raw_len;\n\
        int32_t *c_r_raw_int;\n\
};\n"

STRUCT_POPULATE_START = "\n\nstruct test_vector test_vectors[] = {\n"
STRUCT_POPULATE = "\n\
	{\n\
        .method = NULL,\n\
        .method_len = 0,\n\
        \n\
        .SUITES_I = NULL,\n\
        .SUITES_I_len = 0,\n\
        \n\
        .SUITES_R = NULL,\n\
        .SUITES_R_len = 0,\n\
        \n\
        .x_raw = NULL,\n\
        .x_raw_len = 0,\n\
        \n\
        .g_x_raw = NULL,\n\
        .g_x_raw_len = 0,\n\
        \n\
        .g_x = NULL,\n\
        .g_x_len = 0,\n\
        \n\
        .c_i = NULL,\n\
        .c_i_len = 0,\n\
        \n\
        .ead_1 = NULL,\n\
        .ead_1_len = 0,\n\
        \n\
        .message_1 = NULL,\n\
        .message_1_len = 0,\n\
        \n\
        .y_raw = NULL,\n\
        .y_raw_len = 0,\n\
        \n\
        .g_y_raw = NULL,\n\
        .g_y_raw_len = 0,\n\
        \n\
        .g_y = NULL,\n\
        .g_y_len = 0,\n\
        \n\
        .g_xy_raw = NULL,\n\
        .g_xy_raw_len = 0,\n\
        \n\
        .salt_raw = NULL,\n\
        .salt_raw_len = 0,\n\
        \n\
        .prk_2e_raw = NULL,\n\
        .prk_2e_raw_len = 0,\n\
        \n\
        .sk_r_raw = NULL,\n\
        .sk_r_raw_len = 0,\n\
        \n\
        .pk_r_raw = NULL,\n\
        .pk_r_raw_len = 0,\n\
        \n\
        .prk_3e2m_raw = NULL,\n\
        .prk_3e2m_raw_len = 0,\n\
        \n\
        .c_r = NULL,\n\
        .c_r_len = 0,\n\
        \n\
        .h_message_1_raw = NULL,\n\
        .h_message_1_raw_len = 0,\n\
        \n\
        .h_message_1 = NULL,\n\
        .h_message_1_len = 0,\n\
        \n\
        .input_th_2 = NULL,\n\
        .input_th_2_len = 0,\n\
        \n\
        .th_2_raw = NULL,\n\
        .th_2_raw_len = 0,\n\
        \n\
        .th_2 = NULL,\n\
        .th_2_len = 0,\n\
        \n\
        .id_cred_r = NULL,\n\
        .id_cred_r_len = 0,\n\
        \n\
        .cred_r = NULL,\n\
        .cred_r_len = 0,\n\
        \n\
        .ead_2 = NULL,\n\
        .ead_2_len = 0,\n\
        \n\
        .info_mac_2 = NULL,\n\
        .info_mac_2_len = 0,\n\
        \n\
        .mac_2_raw = NULL,\n\
        .mac_2_raw_len = 0,\n\
        \n\
        .mac_2 = NULL,\n\
        .mac_2_len = 0,\n\
        \n\
        .m_2 = NULL,\n\
        .m_2_len = 0,\n\
        \n\
        .sig_or_mac_2_raw = NULL,\n\
        .sig_or_mac_2_raw_len = 0,\n\
        \n\
        .sig_or_mac_2 = NULL,\n\
        .sig_or_mac_2_len = 0,\n\
        \n\
        .plaintext_2 = NULL,\n\
        .plaintext_2_len = 0,\n\
        \n\
        .info_keystream_2 = NULL,\n\
        .info_keystream_2_len = 0,\n\
        \n\
        .keystream_2_raw = NULL,\n\
        .keystream_2_raw_len = 0,\n\
        \n\
        .ciphertext_2_raw = NULL,\n\
        .ciphertext_2_raw_len = 0,\n\
        \n\
        .ciphertext_2 = NULL,\n\
        .ciphertext_2_len = 0,\n\
        \n\
        .message_2 = NULL,\n\
        .message_2_len = 0,\n\
        \n\
        .sk_i_raw = NULL,\n\
        .sk_i_raw_len = 0,\n\
        \n\
        .pk_i_raw = NULL,\n\
        .pk_i_raw_len = 0,\n\
        \n\
        .prk_4x3m_raw = NULL,\n\
        .prk_4x3m_raw_len = 0,\n\
        \n\
        .input_TH_3 = NULL,\n\
        .input_TH_3_len = 0,\n\
        \n\
        .th_3_raw = NULL,\n\
        .th_3_raw_len = 0,\n\
        \n\
        .th_3 = NULL,\n\
        .th_3_len = 0,\n\
        \n\
        .id_cred_i = NULL,\n\
        .id_cred_i_len = 0,\n\
        \n\
        .cred_i = NULL,\n\
        .cred_i_len = 0,\n\
        \n\
        .ead_3 = NULL,\n\
        .ead_3_len = 0,\n\
        \n\
        .info_mac_3 = NULL,\n\
        .info_mac_3_len = 0,\n\
        \n\
        .mac_3_raw = NULL,\n\
        .mac_3_raw_len = 0,\n\
        \n\
        .mac_3 = NULL,\n\
        .mac_3_len = 0,\n\
        \n\
        .m_3 = NULL,\n\
        .m_3_len = 0,\n\
        \n\
        .sig_or_mac_3_raw = NULL,\n\
        .sig_or_mac_3_raw_len = 0,\n\
        \n\
        .sig_or_mac_3 = NULL,\n\
        .sig_or_mac_3_len = 0,\n\
        \n\
        .p_3 = NULL,\n\
        .p_3_len = 0,\n\
        \n\
        .a_3 = NULL,\n\
        .a_3_len = 0,\n\
        \n\
        .info_k_3 = NULL,\n\
        .info_k_3_len = 0,\n\
        \n\
        .k_3_raw = NULL,\n\
        .k_3_raw_len = 0,\n\
        \n\
        .info_iv_3 = NULL,\n\
        .info_iv_3_len = 0,\n\
        \n\
        .iv_3_raw = NULL,\n\
        .iv_3_raw_len = 0,\n\
        \n\
        .ciphertext_3_raw = NULL,\n\
        .ciphertext_3_raw_len = 0,\n\
        \n\
        .ciphertext_3 = NULL,\n\
        .ciphertext_3_len = 0,\n\
        \n\
        .message_3 = NULL,\n\
        .message_3_len = 0,\n\
        \n\
        .input_th_4 = NULL,\n\
        .input_th_4_len = 0,\n\
        \n\
        .th_4_raw = NULL,\n\
        .th_4_raw_len = 0,\n\
        \n\
        .th_4 = NULL,\n\
        .th_4_len = 0,\n\
        \n\
        .ead_4 = NULL,\n\
        .ead_4_len = 0,\n\
        \n\
        .p_4 = NULL,\n\
        .p_4_len = 0,\n\
        \n\
        .a_4 = NULL,\n\
        .a_4_len = 0,\n\
        \n\
        .info_k_4 = NULL,\n\
        .info_k_4_len = 0,\n\
        \n\
        .k_4_raw = NULL,\n\
        .k_4_raw_len = 0,\n\
        \n\
        .info_iv_4 = NULL,\n\
        .info_iv_4_len = 0,\n\
        \n\
        .iv_4_raw = NULL,\n\
        .iv_4_raw_len = 0,\n\
        \n\
        .ciphertext_4_raw = NULL,\n\
        .ciphertext_4_raw_len = 0,\n\
        \n\
        .ciphertext_4 = NULL,\n\
        .ciphertext_4_len = 0,\n\
        \n\
        .message_4 = NULL,\n\
        .message_4_len = 0,\n\
        \n\
        .oscore_aead_alg = NULL,\n\
        \n\
        .oscore_hash_alg = NULL,\n\
        \n\
        .client_sender_id_raw = NULL,\n\
        .client_sender_id_raw_len = 0,\n\
        \n\
        .server_sender_id_raw = NULL,\n\
        .server_sender_id_raw_len = 0,\n\
        \n\
        .info_oscore_secret = NULL,\n\
        .info_oscore_secret_len = 0,\n\
        \n\
        .oscore_secret_raw = NULL,\n\
        .oscore_secret_raw_len = 0,\n\
        \n\
        .info_oscore_salt = NULL,\n\
        .info_oscore_salt_len = 0,\n\
        \n\
        .oscore_salt_raw = NULL,\n\
        .oscore_salt_raw_len = 0,\n\
        \n\
        .key_update_nonce_raw = NULL,\n\
        .key_update_nonce_raw_len = 0,\n\
        \n\
        .prk_4x3m_key_update_raw = NULL,\n\
        .prk_4x3m_key_update_raw_len = 0,\n\
        \n\
        .oscore_secret_key_update_raw = NULL,\n\
        .oscore_secret_key_update_raw_len = 0,\n\
        \n\
        .oscore_salt_key_update_raw = NULL,\n\
        .oscore_salt_key_update_raw_len = 0,\n\
        \n\
        .ca_r = NULL,\n\
        .ca_r_len = 0,\n\
        \n\
        .ca_i = NULL,\n\
        .ca_i_len = 0,\n\
        \n\
        .ca_r_pk = NULL,\n\
        .ca_r_pk_len = 0,\n\
        \n\
        .ca_i_pk = NULL,\n\
        .ca_i_pk_len = 0,\n\
        \n\
        .i_raw = NULL,\n\
        .i_raw_len = 0,\n\
        \n\
        .g_i_raw = NULL,\n\
        .g_i_raw_len = 0,\n\
        \n\
        .r_raw = NULL,\n\
        .r_raw_len = 0,\n\
        \n\
        .g_r_raw = NULL,\n\
        .g_r_raw_len = 0,\n\
        \n\
        .c_i_raw = NULL,\n\
        .c_i_raw_len = 0,\n\
        .c_i_raw_int = NULL,\n\
        \n\
        .c_r_raw = NULL,\n\
        .c_r_raw_len = 0,\n\
        .c_r_raw_int = NULL,\n\
	},\n\
"
STRUCT_POPULATE_END = "};"


def print_c_array(in_string):

    cnt = 1
    if type(in_string) is str:
        out_string = "[] = {\n\t"
        for i in range(0, len(in_string), 2):
            out_string = out_string + "0x" + in_string[i] + in_string[i + 1]

            if i != len(in_string) - 2:
                out_string = out_string + ", "
                if cnt == 8:
                    out_string = out_string + "\n\t"
                    cnt = 0
            else:
                out_string = out_string + "};\n"
            cnt = cnt + 1

        if len(in_string) == 0:
            out_string = out_string + "};\n"

    if type(in_string) is int:
        out_string = " = " + str(in_string) + ";\n"

    # print(out_string)
    return out_string


def get_len_str(i, data):
    if type(data["test_vector_1"][i]) is str:
        return str(len(data["test_vector_1"][i]) >> 1)
    else:
        return "1"


def populate_struct_body(input, val="dummy", key="dummy", array_name="dummy"):

    pattern_str_len = "        ." + key + "_len = 0"
    repl_str_len = "        ." + key + "_len = sizeof(" + array_name + ")"
    pattern_str_val = "        ." + key + " = NULL"
    repl_str_val = "        ." + key + " = " + array_name

    pattern_int_val = "        ." + key + " = NULL"
    repl_int_val = "        ." + key + " = &" + array_name

    pattern_c_x_int_val = "        ." + key + "_int = NULL"
    #     repl_c_x_str_val = "        ." + key + \
    #         " =  {BSTR, {sizeof(" + array_name + "), " + array_name + "}}"
    repl_c_x_int_val = "        ." + key + "_int" + " =  &" + array_name

    #     if (key == "c_r_raw") or (key == "c_i_raw"):
    #         if isinstance(val, str):
    #             return re.sub(pattern_c_x_str_val, repl_c_x_str_val, input)
    #         if isinstance(val, int):
    #             return re.sub(pattern_c_x_str_val, repl_c_x_int_val, input)

    if isinstance(val, str):
        changed_len = re.sub(pattern_str_len, repl_str_len, input)
        changed_val_len = re.sub(pattern_str_val, repl_str_val, changed_len)
        return changed_val_len

    if isinstance(val, int):
        if (key == "c_r_raw") or (key == "c_i_raw"):
            return re.sub(pattern_c_x_int_val, repl_c_x_int_val, input)
        changed_val_len = re.sub(pattern_int_val, repl_int_val, input)
        return changed_val_len


def main():
    with open(in_out_path + in_file, "r") as in_fp:
        data = json.load(in_fp)

    data_arrays = "\n"
    struct_body_out = "\n"

    test_vector_labels = list(data.keys())
    # print(test_vector_labels[0])
    vec_num = test_vector_labels[0]

    for vec_num in test_vector_labels:
        data_arrays += "\n/***************** " + vec_num + " ************/\n\n "
        test_vector_elements = data[vec_num]
        # print(test_vector_elements.keys())
        # print(test_vector_elements.values())

        struct_body = populate_struct_body(STRUCT_POPULATE)
        for key in test_vector_elements.keys():
            # print(key, test_vector_elements[key])
            array_name = vec_num + "_" + key
            type = test_vector_elements[key]

            # if the value of an element is a int save it as int_32
            if isinstance(type, int):
                data_arrays = (
                    data_arrays
                    + "int32_t "
                    + array_name
                    + print_c_array(test_vector_elements[key])
                )

            # if the value of an element is a string save it in uint8_t array
            if isinstance(type, str):
                data_arrays = (
                    data_arrays
                    + "static const uint8_t "
                    + array_name
                    + print_c_array(test_vector_elements[key])
                )

            struct_body = populate_struct_body(struct_body, type, key, array_name)

        struct_body_out += "/*--------------- " + vec_num + " ------------*/\n "
        struct_body_out += struct_body

    output = (
        HEADER
        + INCLUDES
        + STRUCT_DEF
        + data_arrays
        + STRUCT_POPULATE_START
        + struct_body_out
        + STRUCT_POPULATE_END
    )
    with open(in_out_path + out_file, "w") as out_fp:
        out_fp.write(output)


if __name__ == "__main__":
    main()
