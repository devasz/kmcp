; boot sector: cli; hlt (dead hang: nothing can wake it)
bits 16
org 0x7c00
    cli
.dead:
    hlt
    jmp .dead
times 510-($-$$) db 0
dw 0xaa55
