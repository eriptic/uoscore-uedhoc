/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef OSCORE_COSE_H
#define OSCORE_COSE_H

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief Decrypt the ciphertext
 * @param in_ciphertext: input ciphertext to be decrypted
 * @param out_plaintext: output plaintext
 * @param nonce the nonce
 * @param aad the aad
 * @param recipient_key the recipient key
 * @return err
 */
enum err oscore_cose_decrypt(struct byte_array *in_ciphertext,
			     struct byte_array *out_plaintext,
			     struct byte_array *nonce, struct byte_array *aad,
			     struct byte_array *recipient_key);

/**
 * @brief Encrypt the plaintext
 * @param in_plaintext: input plaintext to be encrypted
 * @param out_ciphertext: output ciphertext with authentication tag (8 bytes)
 * @param nonce the nonce
 * @param sender_aad the aad
 * @param key the sender key
 * @return err
 */
enum err oscore_cose_encrypt(struct byte_array *in_plaintext,
			     struct byte_array *out_ciphertext,
			     struct byte_array *nonce,
			     struct byte_array *sender_aad,
			     struct byte_array *key);
#endif
