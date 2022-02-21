# uOSCORE / uEDHOC 

This repository contains C implementations  for constrained (and non-constrained) devices of the IETF protocols:

* [OSOCRE (RFC8613)](https://tools.ietf.org/html/rfc8613) and
* [EDHOC (draft-ietf-lake-edhoc-12 )](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-12). 

Main features of uOSCORE and uEDHOC are their independence from the OS, cryptographic engine and in the case of uEDHOC transport protocol. Additionally,  uOSCORE and uEDHOC use only stack memory (no heap).

For more background and evaluation in terms of speed, RAM and flash requirements see our paper [The Cost of OSCORE and EDHOC for Constrained Devices](https://arxiv.org/pdf/2103.13832.pdf).

## How to Build and Link

* check the configurations in `makefile_config.mk` and adjust them if necessary
* run `make` 
* link the static library `build/libuoscore-uedhoc.a` in your project

## Project (Folder) Structure

```
.
|---cddl_models/
|---externals/
|---inc/
|---samples/
|---scripts/
|---src/
|---test/
|---test_vectors/
```
* The folder `cddl_models` contains CDDL models for all CBOR structures.
* The folder `externals` contains the external libraries and tools as git submodules.
* The folder `inc` contains all header file.
* The folder `samples` contains some usage examples.
* The folder `scripts` contains scripts for generatinc C code from CDDL models and converting the json formatted EDHOC test vectors to a C header
* The folder `src` contains all source file.
* The folder `test` contains automated tests. 
* The folder `test_vectors` contains tests vectors. 

## API and Usage Model

#### uOSCORE

The API of uOSCORE consists of three functions: 
* `oscore_context_init()`,
*  `coap2oscore()` and 
*  `oscore2coap()`.

`coap2oscore()` and `oscore2coap()` convert CoAP to OSCORE packets and vice versa. `oscore_context_init()` initializes the OSCORE security context. 

First, `oscore_context_init()` function needs to be called on the client and server side, then `coap2oscore()` and `oscore2coap()`  are called just before sending or receiving packets over the network.

<img src="oscore_usage.svg" alt="drawing" width="600"/>


#### uEDHOC

The API of uEDHOC consists of four functions:
*  `ephemeral_dh_key_gen()`
* `edhoc_initiator_run()`,
* `edhoc_responder_run()`,
* `edhoc_exporter()`,

`ephemeral_dh_key_gen()` is used to generate fresh ephemeral DH keys before running the protocol. This function requires a random seed suable for cryptographic purposes. `edhoc_initiator_run()` and `edhoc_responder_run() ` has to be called on the initiator and responder side respectively. They return the External Authorization data `EAD_x`,  the derived shared secret `PRK_4x3m` and the transcript hash `TH_4`.   `PRK_4x3m` and `TH_4` are used as inputs for `edhoc_exporter()` to derive application specific keys, e.g., OSCORE master secret and OSCORE master salt.

The EDHOC protocol requires the exchange of three messages which is independent of the underlying message transport protocol. For example [appendix-A.3 in the EDHOC specification](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-12#appendix-A.3) describes how  EDHOC can be transferred over CoAP, however CoAP is not mandatory. In order to be independent of the transport protocol uEDHOC uses two callback functions which need to be implemented by the user for handling the sending and receiving of messages. These functions are:

```c
/**
 * @brief   The user should call inside this function its send function. 
 *
 * 
 * @param   sock a pointer used to identify the rx chanel, 
 *          e.g. a socket handler
 * @param   data pointer to the data to be send
 * @param   data_len length of the data
 */
enum err tx(void *sock, uint8_t *data, uint32_t data_len);

/**
 * @brief   The user should call inside this function its receive 
 *          function and copy the received data in the buffer <data>.
 *          The length of the buffer <data> must be 
 *          checked before copying into it by using <data_len>. 
 *          After copying the length of the received data should be written 
 *          in <data_len>.
 *
 * 
 * @param   sock a pointer used to identify the rx chanel, 
 *          e.g. a socket handler
 * @param   data pointer to a buffer where the edhoc message must be copied 
 * @param   data_len length of the received data. When this function is 
 *          called inside EDHOC <data_len> is initialized with the actual 
 *          available length of the <data>.
 */
enum err rx(void *sock, uint8_t *data, uint32_t *data_len);
```



## Supported Cipher Suites

##### uOSCORE

| Algorithms                  |
| --------------------------- |
| AES-CCM-16-64-128,  SHA-256 |

##### uEDHOC


| Suit | Algorithms                                                                 |
| ---- | -------------------------------------------------------------------------- |
| 0    | AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA, AES-CCM-16-64-128, SHA-256   |
| 1    | AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA, AES-CCM-16-64-128, SHA-256 |
| 2    | AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES-CCM-16-64-128, SHA-256    |
| 3    | AES-CCM-16-128-128, SHA-256, 16, P-256, ES256, AES-CCM-16-64-128, SHA-256  |



## Using the Samples

The samples contained in `samples/` are supposed to enable the test and verification of a real OSCORE or EDHOC message exchange between two entities. There are samples that can be run on microcontrollers, e.g. NRF5x (using ZephyrOS) and samples that can be run on Linux systems.

When using the samples for microcontroller , they have to be connected to an IPv6 network, which can be done with an IPv6 over BLE border router, using Bluetooth on the constrained devices. For further instructions on how to set up the border router on a Raspberry Pi, see [blerouter](externals/blerouter/README.MD).

* **OSCORE Between a Microcontroller (e.g. nrf52832) as a Server and Linux Host as a Client** 

  The `oscore_device` samples suggest a use of a microcontroller, (e.g. nrf52832) as an OSCORE server and a Linux machine as an OSCORE client. Therefore setting up the network as described in [blerouter](externals/blerouter/README.MD) is required.
  As this is a frequent error source: make sure that all addresses are set up correctly in the blerouter.sh script, the samples/oscore_linux/client/src/main.cpp file and the samples/oscore_device/server/prj.conf file.

  * Configure and build OSCORE server on a microcontroller (nrf52832) using the Zephyr's build tool west 

    * open a terminal and cd to samples/oscore/device/server 

    ```bash
    source <path to zephyr root>/zephyrproject/zephyr/zephyr-env.sh
    west build -b=nrf52dk_nrf52832
    west flash
    ```

    * The server is now reachable under the specified address and can be supplied with CoAP and OSCORE messages.

  * On a Raspberry Pi start externals/blerouter

    ```bash
    sudo ./blerouter.sh -d OscoreServer
    # if it works correctly you should see somthink like:
    # [18:27:47] scanning for devices
    # connect to D9:A4:16:41:CC:2D OscoreServer
    # [18:27:54] connected with D9:A4:16:41:CC:2D OscoreServer
    # [18:27:57] connected with D9:A4:16:41:CC:2D OscoreServer
    # ...
    ```

    

  * Configure OSCORE Linux client

    * open a terminal and cd to samples/oscore_linux/client

    * run ```make``` and ```./build/oscore_linux_client to send CoAP and OSCORE messages to the OSCORE server

* **OSCORE Between to Linux Hosts**

  Adjust the IP address of the other party in  samples/oscore_linux/client and samples/oscore_linux/server and run them.

* **EDHOC**

  Two parties are involved in a EDHOC message exchange -- an initiator (typically client) and a responder (typically server). The `edhoc_device` samples suggest the communication between a microcontroller and a Linux machine, with the network set up as described in [blerouter](externals/blerouter/README.MD). However, there can also be two Linux machines or two microcontrollers performing the EDHOC exchange, with the latter case requiring a second RPi set up as border router and connected to the second microcontroller. The addresses have to be changed accordingly in the prj.conf files. The following describes the setup for the EDHOC exchange between microcontroller and linux machine.

  * Microcontroller as initiator and Linux machine as responder

      * open a terminal and cd to samples/edhoc_linux/responder
      * make sure the IP addresses are correct
      * run ```make``` and ```./build/responder``` to build and run
      * the linux responder can now be supplied with an EDHOC requests
      * cd to samples/edhoc_device/initiator
      
      ```bash
      source <path to zephyr root>/zephyrproject/zephyr/zephyr-env.sh
      west build -b=nrf52dk_nrf52832
      west flash
      ```
      * set up the border router as described here [blerouter](externals/blerouter/README.MD)
      
      * the EDHOC message exchange should take place and the results should be printed on the linux machine - the message traffic can be captured and viewed using wireshark on the border router
      
  * Linux machine as initiator and Microcontroller as responder
    
    * open a terminal and cd to samples/edhoc_device/responder
    
    ```bash
    source <path to zephyr root>/zephyrproject/zephyr/zephyr-env.sh
    west build -b=nrf52dk_nrf52832
    west flash
    ```
    
    * set up the border router as described here [blerouter](externals/blerouter/README.MD)
    * the Microcontroller can now be supplied with an EDHOC request
    * cd to samples/edhoc_linux/initiator
    * run ```make``` and ```./build/initiator``` to build and run
    * the EDHOC message exchange should take place and the results should be printed on the linux machine - the message traffic can be captured and viewed using wireshark


## Using Different Cryptographic Libraries or Hardware Accelerators

The logic of uOSCORE and uEDHOC is independent form the cryptographic library, i.e., the cryptographic library can easily be exchanged by the user. For that the user needs to provide implementations for the functions specified in `crypto_wrapper.c`. 

