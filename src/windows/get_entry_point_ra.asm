PUBLIC get_entry_point_ra
EXTERN mainCRTStartup : PROC

.code

get_entry_point_ra PROC
    mov rax, mainCRTStartup     ; put in rax the address of entrypoint
    ret                         ; return that value
get_entry_point_ra ENDP