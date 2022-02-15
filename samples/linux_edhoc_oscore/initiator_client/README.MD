# Sample showing the combined usage of EDHOC and OSCORE 

* EDHOC role is initiator
* OSCORE role is client

* First a Master secret is derived by using EDHOC
* Then a CoAP/OSCORE client alternately requests a regular resource and an OSCORE secured resource.
