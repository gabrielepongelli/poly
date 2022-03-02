.section .text

.globl mainCRTStartup               # entrypoint symbol

.globl get_entry_point_ra           # export this function
get_entry_point_ra:
    lea mainCRTStartup(%rip), %rax  # put in rax the address of entrypoint
    ret                             # return that value

.end