; boot sector: report a guest panic through pvpanic (port 0x505), then idle
bits 16
org 0x7c00
    mov dx, 0x505
    mov al, 1
    out dx, al
.idle:
    hlt
    jmp .idle
times 510-($-$$) db 0
dw 0xaa55
