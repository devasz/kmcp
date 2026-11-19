; boot sector: real -> 32-bit protected mode, enable AMD SVM, VMRUN a one-instruction guest (cpuid, intercepted),
; then report the #VMEXIT code on COM1: 'K' = SVM_EXIT_CPUID (0x72), 'F' = anything else.
bits 16
org 0x7c00
VMCB   equ 0x10000
HSAVE  equ 0x11000
    cli
    xor ax, ax
    mov ds, ax
    lgdt [gdtr]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    jmp 0x08:pm
bits 32
pm:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x7000
    mov ecx, 0xC0000080          ; EFER.SVME
    rdmsr
    or eax, 1 << 12
    wrmsr
    mov ecx, 0xC0010117          ; VM_HSAVE_PA
    xor edx, edx
    mov eax, HSAVE
    wrmsr
    mov edi, VMCB
    xor eax, eax
    mov ecx, 1024
    rep stosd
    mov dword [VMCB + 0x0c], 1 << 18      ; intercept CPUID
    mov dword [VMCB + 0x10], 1            ; intercept VMRUN (mandatory)
    mov dword [VMCB + 0x58], 1            ; ASID
    mov dword [VMCB + 0x400 + 0x00], 0x0c93 << 16 | 0x10   ; ES
    mov dword [VMCB + 0x400 + 0x10], 0x0c9b << 16 | 0x08   ; CS
    mov dword [VMCB + 0x400 + 0x20], 0x0c93 << 16 | 0x10   ; SS
    mov dword [VMCB + 0x400 + 0x30], 0x0c93 << 16 | 0x10   ; DS
    mov dword [VMCB + 0x404], 0xffffffff
    mov dword [VMCB + 0x414], 0xffffffff
    mov dword [VMCB + 0x424], 0xffffffff
    mov dword [VMCB + 0x434], 0xffffffff
    mov dword [VMCB + 0x4d0], 1 << 12     ; guest EFER (SVME must be set)
    mov dword [VMCB + 0x558], 0x11        ; guest CR0: PE | ET
    mov dword [VMCB + 0x570], 2           ; RFLAGS
    mov dword [VMCB + 0x578], guest       ; RIP
    mov dword [VMCB + 0x5d8], 0x6000      ; RSP
    mov eax, VMCB
vmrun_site:
    vmrun
    mov edx, 0x3f8
    mov al, 'F'
    cmp dword [VMCB + 0x70], 0x72
    jne .out
    mov al, 'K'
.out:
    out dx, al
.halt:
    hlt
    jmp .halt
guest:
    xor eax, eax
    cpuid
    hlt
align 8
gdt: dq 0
     dq 0x00cf9a000000ffff
     dq 0x00cf92000000ffff
gdtr: dw 23
      dd gdt
times 510-($-$$) db 0
dw 0xaa55
