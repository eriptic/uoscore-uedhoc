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

#include "edhoc.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief                       Verifies a c509 certificate.
 * 
 * @param[in] cert              A native CBOR encoded certificate.
 * @param[in] cred_array        An array containing credentials. 
 * @param[out] pk               Public key contained in the certificate.
 * @param verified              True if the verification is successful.
 * @retval                      Ok or error code.
 */
enum err cert_c509_verify(struct const_byte_array *cert,
			  const struct cred_array *cred_array,
			  struct byte_array *pk, bool *verified);

/**
 * @brief                       Verifies a x509 certificate.
 * 
 * @param[in] cert              A X.509 encoded certificate.
 * @param[in] cred_array        An array containing credentials. 
 * @param[out] pk               Public key contained in the certificate.
 * @param verified              True if the verification is successful.
 * @retval                      Ok or error code.
 */
enum err cert_x509_verify(struct const_byte_array *cert,
			  const struct cred_array *cred_array,
			  struct byte_array *pk, bool *verified);
#endif
