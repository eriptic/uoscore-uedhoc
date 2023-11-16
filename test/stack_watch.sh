# run this script with: "gdb --batch --command=stack_watch.sh build/initiator"


#set a break point at edhoc_initiator_run
b edhoc_initiator_run

# run the program abd stop at edhoc_initiator_run
run

# save the stack pointer in a variable sp_start
set $sp_start = $sp
p $sp_start
p $sp

# dump N bytes before the stack pointer
set $N = 1000
p $N
set $dump_start_addr = $sp - $N
p $dump_start_addr
#x/80xb $dump_start_addr

# overwrite 80 bytes before the sp withe the pattern 0xaa
#call (void*)  memset($sp-80, 0xaa, 80)
#set unwindonsignal on
#call (void*)  memset($dump_start_addr, 0xaa, 1000)

# dump 80 bytes before the stack pointer
p $sp
x/1000xb $dump_start_addr

# step over the edhoc_initiator_run
finish

# dump 80 bytes before the stack pointer
p $sp
x/1000xb $dump_start_addr