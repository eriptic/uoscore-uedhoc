# Tests

This folder contains tests for uoscore and uedhoc. The tests can be executed on an embedded board, e.g., nrf51dk and/or a Linux host. The tests use Zephyr OS for building. 

### How to run:

### Run tests on a Linux host
```bash
cd test/
source <path>/zephyr-env.sh 
rm -rf build/; west build -b=native_posix
west build -t run
```

### Run on an embedded board
```bash
cd test/
source <path>/zephyr-env.sh 
rm -rf build/; west build -b=<board_name>
west flash
```

