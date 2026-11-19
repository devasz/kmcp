; boot sector: print "HELLO\n" on COM1, then idle forever with interrupts enabled (sti; hlt)
bits 16
org 0x7c00
start:
    xor ax, ax
    mov ds, ax
    mov si, msg
.next:
    lodsb
    test al, al
    jz .done
    mov dx, 0x3f8
    out dx, al
    jmp .next
.done:
    sti
.idle:
    hlt
    jmp .idle
msg db "HELLO", 10, 0
times 510-($-$$) db 0
dw 0xaa55
