/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef NVM_H
#define NVM_H

#include "oscore.h"
#include "common/oscore_edhoc_error.h"

enum err ssn_init(bool fresh_master_secret_salt, struct context *c);
enum err ssn_store_in_nvm(struct context *c);
#endif