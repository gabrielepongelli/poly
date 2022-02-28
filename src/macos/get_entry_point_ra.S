.section __TEXT,__text

.globl _main                    # entrypoint symbol

.globl _get_entry_point_ra      # export this function
_get_entry_point_ra:
    lea _main(%rip), %rax       # put in rax the address of entrypoint
    ret                         # return that value

.end