# Tests

This folder contains tests for uoscore and uedhoc. The tests can be executed on an embedded board, e.g., nrf51dk and/or a Linux host. The tests use Zephyr OS for building. 

### How to run:

* source `zephyr-env.sh`,
* if you want to test on a specific board connect the board to your host and open an serial terminal to observe the test results,
* execute `west build -b=<board_name>`
* if an embedded board is used `west flash` 
* if a PC is used `west build -t run`
