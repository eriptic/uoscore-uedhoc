#!/usr/bin/python3
# this script is called form stack_report_gen.sh
from tabulate import tabulate
from dataclasses import dataclass
import os, shutil
import sys
import gdb

output_file = "build_reports/stack_report.html"


def print_summary(d, fkt_name):
    headers = ["measured function", "Used stack"]
    with open(output_file, "a") as f:
        f.write(
            "<br> The following stack consumption is achieved when uoscore-uedhoc is built with the following flags: "
        )
        f.write(arg_flags)
        f.write("<br>")
        f.write(tabulate(d, headers, tablefmt="unsafehtml"))
        f.write("<br>")


def measure_stack_usage_of_function(f):
    gdb.execute("set pagination off")
    bp = gdb.Breakpoint(f.fkt_name)

    gdb.execute("run")
    i = gdb.inferiors()[0]

    measurements = []

    while True:
        # Loop through all break points and measure the stack for each function.
        try:
            # Here we stop at the beginning of the function that we want to profile.
            breakpoint_location = gdb.execute("backtrace 2", False, True)
            sp_start = int(gdb.parse_and_eval("$sp"))
            print("Starting SP: 0x{:08x}".format(sp_start))

            stack_bottom = sp_start - f.max_stack_size
            print("stack_bottom: 0x{:08x}".format(stack_bottom))

            i = gdb.inferiors()[0]
            stack_dump_start = i.read_memory(stack_bottom, f.max_stack_size)

            while True:
                # Step one line until we stepped out of the function.
                gdb.execute("n")
                sp = int(gdb.parse_and_eval("$sp"))
                if sp > sp_start:
                    break

            stack_dump_end = i.read_memory(stack_bottom, f.max_stack_size)

            used_stack_memory = 0
            for i in range(f.max_stack_size):
                if (
                    stack_dump_start.tobytes()[f.max_stack_size - i - 1]
                    != stack_dump_end.tobytes()[f.max_stack_size - i - 1]
                ):
                    used_stack_memory = i

            print("Stack usage: ", used_stack_memory)
            print(breakpoint_location)
            fkt = breakpoint_location.split(" ")[2]
            print("fkt is: ", fkt)

            caller = breakpoint_location.split("#1")[1].split(" ")[-1:]
            print("caller is: ", caller)
            measurements.append([fkt, caller, used_stack_memory])
            gdb.execute("c")
        except gdb.error:
            # We are here when the program went to its end.
            break

    gdb.Breakpoint.delete(bp)
    print_summary(measurements, f.fkt_name)


def main():
    @dataclass
    class Function:
        fkt_name: str
        max_stack_size: int

    gdb.execute("file " + "build/zephyr/zephyr.elf")

    functions = [
        Function("coap2oscore", 1500),
        Function("oscore2coap", 1500),
        Function("edhoc_responder_run", 7000),
        Function("edhoc_initiator_run", 7000),
    ]
    for f in functions:
        measure_stack_usage_of_function(f)

    gdb.execute("q")


if __name__ == "__main__":
    main()
