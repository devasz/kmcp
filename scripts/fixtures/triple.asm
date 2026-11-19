; boot sector: zero-limit IDT then int3 -> #GP -> double fault -> triple fault (CPU shutdown)
bits 16
org 0x7c00
    cli
    lidt [idt0]
    int3
idt0: dw 0
      dd 0
times 510-($-$$) db 0
dw 0xaa55
