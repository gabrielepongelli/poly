.section .text

.globl _start                   # entrypoint symbol

.globl get_entry_point_ra       # export this function
get_entry_point_ra:
    lea _start(%rip), %rax      # put in rax the address of entrypoint
    ret                         # return that value

.end