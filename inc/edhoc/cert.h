/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CERT_H
#define CERT_H

#include <stdint.h>

#include "common/oscore_edhoc_error.h"

/**
 * @brief   Verifies a c509 certificate
 * @param   cert a native CBOR encoded certificate
 * @param   cer_len the length of the certificate
 * @param   cred_array an array containing credentials 
 * @param   cred_num number of elements in cred_array
 * @param   pk public key contained in the certificate
 * @param   pk_len the length pk
 * @param   verified true if verification successful
 * @retval  enum err
 */
enum err cert_c509_verify(const uint8_t *cert, uint32_t cert_len,
			  const struct other_party_cred *cred_array,
			  uint16_t cred_num, uint8_t *pk, uint32_t *pk_len,
			  bool *verified);

/**
 * @brief   Verifies a x509 certificate
 * @param   cert a native CBOR encoded certificate
 * @param   cer_len the length of the certificate
 * @param   cred_array an array containing credentials 
 * @param   cred_num number of elements in cred_array
 * @param   pk public key contained in the certificate
 * @param   pk_len the length pk
 * @param   verified true if verification successful
 * @retval  enum err
 */
enum err cert_x509_verify(const uint8_t *cert, uint32_t cert_len,
			  const struct other_party_cred *cred_array,
			  uint16_t cred_num, uint8_t *pk, uint32_t *pk_len,
			  bool *verified);
#endif
