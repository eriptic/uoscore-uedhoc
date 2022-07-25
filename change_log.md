#### v0.0.1 (12 Apr 2021)

#### v0.0.1 -> v0.1.0 (13 Apr 2021)
* update EDHOC to version v5 of the draft

#### v0.1.0 -> v1.0.0 (25 Jul 2022)
* update EDHOC to version v15 of the draft
* change the CBOR library to zcbor
* change the format of the text vectors
* Support for suites 0,1,2,3
* Support for methods 0,1,2,3
* use CI to run RFC tests
* Build uOSCORE and uEDHOC in a single static library
* Add support for X509 certificates
* improve API
* Add a sample showing the combined usage of OSCORE and EDHOC
* Add support for P256 and use mbedtls as crypto back-end
* Add replay window and sequence number checking for OSCORE
* add additional compiler warning flags 