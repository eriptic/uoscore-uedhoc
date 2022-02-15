# CoAP Client running on debian 9 host

## Abstract

A CoAP ([RFC7252](https://tools.ietf.org/html/rfc7252)) client alternately requesting an EDHOC exchange at the /.well-known/edhoc resource. To be used together with an edhoc responder sample (edhoc_device/responder or edhoc_linux/responder).

## Set Up

* a BLE enabled board (e.g. nRF52832) communicating with a linux client over an IPv6 over BLE border router. To initialize the border router run: "sudo z_con -y 2 -d <MAC_ADDRESS>".

## Dependencies on Other Software Components 

* [tinycbor](https://github.com/zephyrproject-rtos/tinycbor) - a CBOR library
  * provided as git submodule in /externals/tinycbor
* [cantcoap](https://github.com/staropram/cantcoap) - a CoAP library
  * provided as git submodule in externals/cantcoap

## Build and Run

* IPv6 setup:
 * start up device and initialize border router as described in "Set Up"


Then build and run:

```sh
make
./build/linux_coap_client 
```

