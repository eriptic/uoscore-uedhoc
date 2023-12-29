# Benchmark and comparison of OSCORE+EDHOC vs. (D)TLS

## Flash

| Platform             | uoscore-uedhoc 3.0.x | TLS 1.3     | DTLS 1.3    |
| -------------------- | -------------------- | ----------- | ----------- |
| nRF52840 (Cortex M4) | 41,156 Byte          | 52,023 Byte | 58,097 Byte |

Notes:

1) uOSCORE-uEDHOC and (D)TLS are used with P256/AES-128-CCM and X509 certificates. 
2) usocore-uedhoc uses [tinycrypt](https://github.com/intel/tinycrypt) as crypto engine for this evaluation and [zcbor](https://github.com/NordicSemiconductor/zcbor) as CBOR engine. The table shows the total footprint including tinycrypt and zcbor. 
3) The (D)TLS data is obtained with [mbedTLS](https://github.com/Mbed-TLS/mbedtls) and published in Table II in  [Low-Power IoT Communication Security: On the Performance of DTLS and TLS 1.3](https://inria.hal.science/hal-03035402/document)

## RAM

| uoscore-uedhoc 3.0.x with FLA                 | uoscore-uedhoc 3.0.x with VLA                 | TLS 1.3    | DTLS 1.3   |
| --------------------------------------------- | --------------------------------------------- | ---------- | ---------- |
| 5639 Byte (initiator) / 6656 Byte (responder) | 5639 Byte (initiator) / 5351 Byte (responder) | 21692 Byte | 22026 Byte |

Notes:

1. uOSCORE-uEDHOC uses only stack memory. The (D)TLS data includes stack and heap memory as given in Table V in [Low-Power IoT Communication Security: On the Performance of DTLS and TLS 1.3](https://inria.hal.science/hal-03035402/document)

## Bytes-Over-Air

| EDHOC                                                       | TLS 1.3 | DTLS 1.3 |
| ----------------------------------------------------------- | ------- | -------- |
| 808 Byte (exchanging two 293 Byte X.509 certificates)       | 1371    | 1500     |
| 242 Byte (Using pre-established  X.509 certificates)        | -       | -        |
| 101 Byte (Using pre-established static Diffie-Hellman keys) | -       | -        |

## Latency

### Latency for a key exchange with uEDHOC

| Platform                    | EDHOC  exchanging X.509 certificates | EDHOC Using pre-established  X.509 certificates |
| --------------------------- | ------------------------------------ | ----------------------------------------------- |
| ESP32 (Xtensa LX6 @ 160MHz) | 0,402 s                              | 0,294 s                                         |
| nRF52840 (Cortex M4 @64MHz) | 1,1735 s                             | 0,8615 s                                        |
| nRF51822 (Cortex M0 @16MHz) | 11,7205 s                            | 8,622 s                                         |

### Latency for encrypting/decrypting payload data with uOSCORE

| Platform                    | Payload 20 Byte | Payload 50 Byte | Payload 100 Byte | Payload 200 Byte | Payload 500 Byte | Payload 1000 Byte |
| --------------------------- | --------------- | --------------- | ---------------- | ---------------- | ---------------- | ----------------- |
| ESP32 (Xtensa LX6 @ 160MHz) | 475 us          | 671 us          | 977 us           | 1585 us          | 3500 us          | 6600 us           |
| nRF52840 (Cortex M4 @64MHz) | 1801 us         | 2533 us         | 3723 us          | 6073 us          | 13519 us         | 25665 us          |
| nRF51822 (Cortex M0 @16MHz) | 9613 us         | 14069 us        | 20508 us         | 33356 us         | 74005 us         | 140381 us         |

Notes:

1. All latency numbers are pure latency caused by computations. No data was send or received. The sending/receiving was emulated off-line.
2. [Tinycrypt](https://github.com/intel/tinycrypt) was used as cryptographic engine.
