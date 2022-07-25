/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CREDENTIALS_SELECT_H_
#define CREDENTIALS_SELECT_H_

/*Test vector description*/
/*

Macro            | mode                          | RPK/Cert | suite | Ref [1]
INITIATOR_TEST_1 | INITIATOR_SK_RESPONDER_SK     | RPK x5t  | 0     | 1-290
RESPONDER_TEST_1 | INITIATOR_SK_RESPONDER_SK     | RPK x5t  | 0     | 1-290
INITIATOR_TEST_2 | INITIATOR_SDHK_RESPONDER_SDHK | RPK kid  | 0     | 292-540
RESPONDER_TEST_2 | INITIATOR_SDHK_RESPONDER_SDHK | RPK kid  | 0     | 292-540
INITIATOR_TEST_3 | INITIATOR_SK_RESPONDER_SK     | x5chain  | 0     | non
RESPONDER_TEST_3 | INITIATOR_SK_RESPONDER_SK     | x5chain  | 0     | non
INITIATOR_TEST_4 | INITIATOR_SDHK_RESPONDER_SDHK | x5chain  | 0     | non
RESPONDER_TEST_5 | INITIATOR_SDHK_RESPONDER_SDHK | x5chain  | 0     | non


[1]: https://github.com/EricssonResearch/EDHOC/blob/master/Test%20Vectors/vectors.txt

*/

//#define INITIATOR_TEST_1
#define RESPONDER_TEST_1

//#define INITIATOR_TEST_2
//#define RESPONDER_TEST_2

//#define INITIATOR_TEST_3
//#define RESPONDER_TEST_3

//#define INITIATOR_TEST_4
//#define RESPONDER_TEST_4

#endif /* CREDENTIALS_SELECT_H_ */
