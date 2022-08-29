# EDHOC Constrained Device Samples

## General
This folder contains two samples intended to be executed on a constrained device

* initiator - EDHOC initiator running on top of a CoAP client
* responder - EDHOC responder running on top of a CoAP server

Tested on 

* initiator - tested on nRF52840 with IPv6 over BLE
* responder - tested on nRF52840 with IPv6 over BLE

## Requirements
* Zephyr OS is needed for building these samples.
* A BLE board is needed for testing (Tested with nrf52840dk_nrf52840)
* A Linux computer with BLE (Tested on Debian 11)

## Setup 1: nRF52840 responder - Linux host initiator
* connect the BLE board to the computer used for building the samples over USB.
* In the directory `samples/zephyr_edhoc/responder` build and flash the sample:
```bash
west build -b=nrf52840dk_nrf52840
west flash
```
Optionally the board can be connected to a serial terminal for observing status messages.

* Run the script `scripts/ble_connect.sh` as root on a Linux host in order to establish IPv6 over BLE connection between the Linux host and the board.
```bash
sudo ./ble_connect.sh -d EdhocResponder
``` 
* Once the board is flashed and connected it prints the following output:
```bash
uart:~$ *** Booting Zephyr OS build zephyr-v3.1.0-4283-g5108c4f21d3d  ***
[00:00:00.264,709] <inf> bt_hci_core: HW Platform: Nordic Semiconductor (0x0002)
[00:00:00.264,739] <inf> bt_hci_core: HW Variant: nRF52x (0x0002)
[00:00:00.264,770] <inf> bt_hci_core: Firmware: Standard Bluetooth controller (0x00) Version 3.1 Build 99
[00:00:00.265,686] <inf> bt_hci_core: Identity: D0:21:3D:B1:36:09 (random)
[00:00:00.265,716] <inf> bt_hci_core: HCI: version 5.3 (0x0c) revision 0x0000, manufacturer 0x05f1
[00:00:00.265,716] <inf> bt_hci_core: LMP: version 5.3 (0x0c) subver 0xffff
uart:~$ IPv6 server with address 2001:db8::1 started!
waiting to receive message 1...
waiting to receive in rx()
```
* On the Linux host in the folder `samples/linux_edhoc/initiator` build and run the initiator:
```bash
make
./build/initiator
``` 
* Both parties should run the EDHOC protocol to an end and derive the same shared secret. The output on both sides -- initiator and responder should look like this:
```bash
PRK_out (size 32):
        83 90 E7 65 66 2F 4F 51 3D B1 A4 30 66 BD DA 43 
        27 C9 D1 0F A2 D9 28 08 2A 87 2B BF CA 78 CA 2A 
info (size 4):
        0A 40 18 20 
prk_exporter (size 32):
        A7 A0 17 A1 69 6B A3 E1 CE D7 95 E1 ED F9 19 C1 
        4B 4B FE C3 42 2E 12 80 9D B3 35 1D 1A E7 74 FA 
info (size 3):
        00 40 10 
OSCORE Master Secret (size 16):
        67 27 8F A7 7C 9F 4B 5E CB 00 46 6F F5 FA 87 F7 
info (size 3):
        01 40 08 
OSCORE Master Salt (size 8):
        67 FF 58 07 7B DB E2 AC 
```

## Setup 1: nRF52840 initiator - Linux host responder

* make sure that the CoAP port 5683 is open on the Linux host. The port can be opened with UFW (Uncomplicated Firewall).
```bash
sudo ufw allow 5683/udp
sudo ufw enable
sudo ufw status
# which prints:

# Status: active

# To                         Action      From
# --                         ------      ----
# 5683/udp                   ALLOW       Anywhere                  
# 5683/udp (v6)              ALLOW       Anywhere (v6)    
```
* On the Linux host in the folder `samples/linux_edhoc/responder` build and run the responder:
```
make
./build/responder
``` 

* connect the BLE board to the computer used for building the samples over USB.
* In the directory `samples/zephyr_edhoc/initiator` build and flash the sample:
```bash
west build -b=nrf52840dk_nrf52840
west flash
```
Optionally the board can be connected to a serial terminal for observing status messages.

* Run the script `scripts/ble_connect.sh` as root on a Linux host in order to establish IPv6 over BLE connection between the Linux host and the board.
```bash
sudo ./ble_connect.sh -d EdhocInitiator
```
* Both parties should run the EDHOC protocol to an end and derive the same shared secret. 