section .data
    prompt_data db "Please, insert flag: ", 0
    prompt_len equ 20
    
    success_data db "Flag correct, welcome!", 10, 0
    success_len equ 22
    
    const_1 dq 0xDEADBEEF
    const_2 dq 0x13371337
    const_3 dq 0xFEEDFACE
    
    target_0 dq 31089254935
    target_1 dq 35763743827
    target_2 dq 42223415940
    target_3 dq 28191960307
    target_4 dq 18996768081
    target_5 dq 29981803211
    target_6 dq 11129167848

section .bss
    buffer resb 64
    temp_storage resb 32
    state_reg resq 8
    exit_flag resb 1
    xor_key resq 1

section .text
    global _start

_start:
    ; Rendi il codice writable per auto-modificazione
    mov rax, 10                    ; sys_mprotect
    mov rdi, _start               ; indirizzo base
    mov rsi, 0x10000              ; 64KB (ampio margine)
    mov rdx, 7                    ; PROT_READ|PROT_WRITE|PROT_EXEC
    syscall
    
    ; Decripta blocco 0 con chiave iniziale fissa
    mov rax, 0x1337DEADBEEF42     ; chiave iniziale random
    mov rsi, block0_start
    mov rcx, block1_start - block0_start
    
initial_decrypt:
    xor byte [rsi], al
    inc rsi
    ror rax, 8
    loop initial_decrypt
    
    ; Ora esegui blocco 0 decriptato (cade direttamente qui)

block0_start:
    ; === BLOCCO 0 OFFUSCATO (da decriptare inizialmente) ===
    mov r15, 0x41424344
    xor r15, 0x41424344
    mov [exit_flag], r15b
    not byte [exit_flag]
    
    mov rax, 1
    mov rdi, 1
    mov rsi, prompt_data
    mov rdx, prompt_len
    syscall
    
    mov rax, r15  
    mov rdi, rax
    lea rsi, [buffer + 0]
    mov rdx, 63
    syscall
    
    mov rbx, rax           
    dec rbx                 
    cmp byte [buffer + rbx], 10 
    jne skip_newline_removal
    mov byte [buffer + rbx], 0   
    jmp length_check
    
skip_newline_removal:
    mov rbx, rax            

length_check:
    cmp rbx, 35
    setz al
    mov [exit_flag], al
    
    ; Calcolo enc_0 offuscato
    xor rax, rax
    
    movzx rcx, byte [buffer + 0]
    mov rdx, rcx
    shl rdx, 1
    shr rdx, 1
    add rax, rdx
    
    movzx rcx, byte [buffer + 1]
    mov rdx, 200
    sub rdx, 70  ; = 130
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 2]
    mov rdx, 130
    imul rdx, 130  ; = 16900
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 3]
    mov rdx, [const_1]
    xor rdx, rdx  ; zero it
    add rdx, 2197000
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 4]
    mov rdx, 285610000
    mov r8, rdx
    xor rdx, 0x12345
    xor rdx, 0x12345  
    imul rcx, rdx
    add rax, rcx
    
    ; Verifica senza jump di errore - se sbagliato, XOR sarà sbagliato
    mov rbx, [target_0]
    cmp rax, rbx
    setz r8b
    and [exit_flag], r8b
    mov [state_reg + 0], rax
    
    ; XOR blocco 1 con enc_0
    mov [xor_key], rax
    mov rsi, block1_start
    mov rcx, block2_start - block1_start
    
xor_with_enc0:
    mov rdx, [xor_key]
    xor byte [rsi], dl
    inc rsi
    ror qword [xor_key], 8
    loop xor_with_enc0

block1_start:
    ; === BLOCCO 1 OFFUSCATO (criptato con enc_0) ===
    xor rax, rax
    
    movzx rcx, byte [buffer + 5]
    mov rdx, 134
    imul rdx, 134 
    mov r8, rdx
    add r8, 100
    sub r8, 100    
    imul rcx, r8
    add rax, rcx
    
    movzx rcx, byte [buffer + 6]
    mov r8, 322417936
    mov r9, r8
    not r9
    not r9        
    imul rcx, r9
    add rax, rcx
    
    movzx rcx, byte [buffer + 7]
    mov r9, 2406104
    mov r10, r9
    xor r9, r10
    add r9, r10  
    imul rcx, r9
    add rax, rcx
    
    movzx rcx, byte [buffer + 8]
    lea rdx, [rcx * 1 + 0]
    add rax, rdx
    
    movzx r11, byte [buffer + 9]
    mov r12, 134
    mov r13, r11
    bswap r13
    bswap r13     
    imul r13, r12
    add rax, r13
    
    mov rbx, [target_1]
    cmp rax, rbx
    setz r8b
    and [exit_flag], r8b
    mov [state_reg + 8], rax
    
    ; XOR blocco 2 con enc_1
    mov [xor_key], rax
    mov rsi, block2_start
    mov rcx, block3_start - block2_start
    
xor_with_enc1:
    mov rdx, [xor_key]
    xor byte [rsi], dl
    inc rsi
    rol qword [xor_key], 8
    loop xor_with_enc1

block2_start:
    ; === BLOCCO 2 OFFUSCATO (criptato con enc_1) ===
    xor rax, rax
    
    movzx rcx, byte [buffer + 10]
    mov r8, 352275361
    push r8
    pop rdx
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 11]
    mov rdx, 18769
    mov r8, rdx
    shl r8, 1
    shr r8, 1
    imul rcx, r8
    add rax, rcx
    
    movzx rcx, byte [buffer + 12]
    mov rdx, 137
    and rdx, 0xFFFF  
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 13]
    add rax, rcx
    
    movzx rcx, byte [buffer + 14]
    mov rdx, [state_reg + 0] 
    xor rdx, rdx            
    add rdx, 2571353
    imul rcx, rdx
    add rax, rcx
    
    mov rbx, [target_2]
    cmp rax, rbx
    setz r8b
    and [exit_flag], r8b
    mov [state_reg + 16], rax
    
    ; XOR blocco 3 con enc_2
    mov [xor_key], rax
    mov rsi, block3_start
    mov rcx, block4_start - block3_start
    
xor_with_enc2:
    mov rdx, [xor_key]
    xor byte [rsi], dl
    inc rsi
    ror qword [xor_key], 13
    loop xor_with_enc2

block3_start:
    ; === BLOCCO 3 OFFUSCATO (criptato con enc_2) ===
    xor rax, rax
    
    mov r8, [const_1]
    add r8, [const_2] 
    
    movzx rcx, byte [buffer + 15]
    mov r9, 294499921
    imul rcx, r9
    add rax, rcx
    
    movzx rcx, byte [buffer + 16]
    mov rdx, 17161
    lea r9, [rdx + 0]
    imul rcx, r9
    add rax, rcx
    
    movzx rcx, byte [buffer + 17]
    mov rdx, 1
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 18]
    mov rdx, 131
    mov r9, [state_reg + 8]
    xor r9, r9
    add rdx, r9
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 19]
    mov rdx, 2248091
    rol rdx, 1
    ror rdx, 1
    imul rcx, rdx
    add rax, rcx
    
    mov rbx, [target_3]
    cmp rax, rbx
    setz r8b
    and [exit_flag], r8b
    mov [state_reg + 24], rax
    
    ; XOR blocco 4 con enc_3
    mov [xor_key], rax
    mov rsi, block4_start
    mov rcx, block5_start - block4_start
    
xor_with_enc3:
    mov rdx, [xor_key]
    xor byte [rsi], dl
    inc rsi
    rol qword [xor_key], 13
    loop xor_with_enc3

block4_start:
    ; === BLOCCO 4 (criptato con enc_3) ===
    xor rax, rax
    
    movzx rcx, byte [buffer + 20]
    mov rdx, 2628072
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 21]
    add rax, rcx
    
    movzx rcx, byte [buffer + 22]
    mov rdx, 19044
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 23]
    mov rdx, 138
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 24]
    mov r8, 362673936
    imul rcx, r8
    add rax, rcx
    
    mov rbx, [target_4]
    cmp rax, rbx
    setz r8b
    and [exit_flag], r8b
    
    ; XOR blocco 5 con enc_4
    mov [xor_key], rax
    mov rsi, block5_start
    mov rcx, block6_start - block5_start
    
xor_with_enc4:
    mov rdx, [xor_key]
    xor byte [rsi], dl
    inc rsi
    ror qword [xor_key], 5
    loop xor_with_enc4

block5_start:
    ; === BLOCCO 5 (criptato con enc_4) ===
    xor rax, rax
    
    movzx rcx, byte [buffer + 25]
    mov rdx, 2352637
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 26]
    add rax, rcx
    
    movzx rcx, byte [buffer + 27]
    mov rdx, 17689
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 28]
    mov r8, 312900721
    imul rcx, r8
    add rax, rcx
    
    movzx rcx, byte [buffer + 29]
    mov rdx, 133
    imul rcx, rdx
    add rax, rcx
    
    mov rbx, [target_5]
    cmp rax, rbx
    setz r8b
    and [exit_flag], r8b
    
    ; XOR blocco 6 con enc_5
    mov [xor_key], rax
    mov rsi, block6_start
    mov rcx, success_section - block6_start
    
xor_with_enc5:
    mov rdx, [xor_key]
    xor byte [rsi], dl
    inc rsi
    rol qword [xor_key], 5
    loop xor_with_enc5

block6_start:
    ; === BLOCCO 6 (criptato con enc_5) ===
    xor rax, rax
    
    movzx rcx, byte [buffer + 30]
    mov rdx, 18225
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 31]
    add rax, rcx
    
    movzx rcx, byte [buffer + 32]
    mov rdx, 2460375
    imul rcx, rdx
    add rax, rcx
    
    movzx rcx, byte [buffer + 33]
    mov r8, 332150625
    imul rcx, r8
    add rax, rcx
    
    movzx rcx, byte [buffer + 34]
    mov rdx, 135
    imul rcx, rdx
    add rax, rcx
    
    mov rbx, [target_6]
    cmp rax, rbx
    setz r8b
    and [exit_flag], r8b

success_section:
    ; === SEZIONE FINALE (criptata con enc_5) ===
    mov rax, 1
    mov rdi, 1
    mov rsi, success_data
    movzx rdx, byte [exit_flag]
    imul rdx, success_len
    syscall
    
    movzx rdi, byte [exit_flag]
    xor rdi, 1
    mov rax, 60
    syscall

program_end:
