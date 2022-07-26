/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef SUPPORTED_ALGORITHM_H
#define SUPPORTED_ALGORITHM_H

/*default HKDF SHA256*/
enum hkdf {
	OSCORE_SHA_256,
};

enum AEAD_algorithm {
	//AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
	OSCORE_AES_CCM_16_64_128 = 10,
};

#define AUTH_TAG_LEN 8
#define NONCE_LEN 13
#define COMMON_IV_LEN 13
#define MASTER_SECRET_LEN_ 16
#define RECIPIENT_ID_BUFF_LEN 8
#define SENDER_KEY_LEN_ MASTER_SECRET_LEN_
#define RECIPIENT_KEY_LEN_ MASTER_SECRET_LEN_

#endif
