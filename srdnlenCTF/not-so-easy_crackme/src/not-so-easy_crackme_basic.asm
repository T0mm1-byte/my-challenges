section .data
    prompt db "Please, insert flag: ", 0
    prompt_len equ $ - prompt - 1
    
    success_msg db "Flag correct, welcome!", 10, 0
    success_len equ $ - success_msg - 1
    
    target_0 dq 31089254935
    target_1 dq 35763743827
    target_2 dq 42223415940
    target_3 dq 28191960307
    target_4 dq 18996768081
    target_5 dq 29981803211
    target_6 dq 11129167848

section .bss
    buffer resb 64          
    exit_flag resb 1       

section .text
    global _start

_start:
    mov byte [exit_flag], 0
    
    mov rax, 1              
    mov rdi, 1              
    mov rsi, prompt
    mov rdx, prompt_len
    syscall
    
    mov rax, 0              
    mov rdi, 0              
    mov rsi, buffer
    mov rdx, 63             
    syscall
    
    mov rbx, rax            
    dec rbx                 
    cmp byte [buffer + rbx], 10  
    cmove rax, rbx          
    mov byte [buffer + rax], 0  
    
    cmp rbx, 35
    setz al                 
    mov [exit_flag], al     

    mov rax, 0
    
    movzx rcx, byte [buffer + 0]
    add rax, rcx
    
    movzx rcx, byte [buffer + 1]
    imul rcx, 130
    add rax, rcx
    
    movzx rcx, byte [buffer + 2]
    imul rcx, 16900
    add rax, rcx
    
    movzx rcx, byte [buffer + 3]
    imul rcx, 2197000
    add rax, rcx
    
    movzx rcx, byte [buffer + 4]
    imul rcx, 285610000
    add rax, rcx
    
    cmp rax, [target_0]
    setz bl                
    and [exit_flag], bl     

    mov rax, 0
    
    movzx rcx, byte [buffer + 5]
    imul rcx, 17956
    add rax, rcx
    
    movzx rcx, byte [buffer + 6]
    imul rcx, 322417936
    add rax, rcx
    
    movzx rcx, byte [buffer + 7]
    imul rcx, 2406104
    add rax, rcx
    
    movzx rcx, byte [buffer + 8]
    add rax, rcx
    
    movzx rcx, byte [buffer + 9]
    imul rcx, 134
    add rax, rcx
    
    cmp rax, [target_1]
    setz bl
    and [exit_flag], bl

    mov rax, 0
    
    movzx rcx, byte [buffer + 10]
    imul rcx, 352275361
    add rax, rcx
    
    movzx rcx, byte [buffer + 11]
    imul rcx, 18769
    add rax, rcx
    
    movzx rcx, byte [buffer + 12]
    imul rcx, 137
    add rax, rcx
    
    movzx rcx, byte [buffer + 13]
    add rax, rcx
    
    movzx rcx, byte [buffer + 14]
    imul rcx, 2571353
    add rax, rcx
    
    cmp rax, [target_2]
    setz bl
    and [exit_flag], bl

    mov rax, 0
    
    movzx rcx, byte [buffer + 15]
    imul rcx, 294499921
    add rax, rcx
    
    movzx rcx, byte [buffer + 16]
    imul rcx, 17161
    add rax, rcx
    
    movzx rcx, byte [buffer + 17]
    add rax, rcx
    
    movzx rcx, byte [buffer + 18]
    imul rcx, 131
    add rax, rcx
    
    movzx rcx, byte [buffer + 19]
    imul rcx, 2248091
    add rax, rcx
    
    cmp rax, [target_3]
    setz bl
    and [exit_flag], bl

    mov rax, 0
    
    movzx rcx, byte [buffer + 20]
    imul rcx, 2628072
    add rax, rcx
    
    movzx rcx, byte [buffer + 21]
    add rax, rcx
    
    movzx rcx, byte [buffer + 22]
    imul rcx, 19044
    add rax, rcx
    
    movzx rcx, byte [buffer + 23]
    imul rcx, 138
    add rax, rcx
    
    movzx rcx, byte [buffer + 24]
    imul rcx, 362673936
    add rax, rcx
    
    cmp rax, [target_4]
    setz bl
    and [exit_flag], bl

    mov rax, 0
    
    movzx rcx, byte [buffer + 25]
    imul rcx, 2352637
    add rax, rcx
    
    movzx rcx, byte [buffer + 26]
    add rax, rcx
    
    movzx rcx, byte [buffer + 27]
    imul rcx, 17689
    add rax, rcx
    
    movzx rcx, byte [buffer + 28]
    imul rcx, 312900721
    add rax, rcx
    
    movzx rcx, byte [buffer + 29]
    imul rcx, 133
    add rax, rcx
    
    cmp rax, [target_5]
    setz bl
    and [exit_flag], bl

    mov rax, 0
    
    movzx rcx, byte [buffer + 30]
    imul rcx, 18225
    add rax, rcx
    
    movzx rcx, byte [buffer + 31]
    add rax, rcx
    
    movzx rcx, byte [buffer + 32]
    imul rcx, 2460375
    add rax, rcx
    
    movzx rcx, byte [buffer + 33]
    imul rcx, 332150625
    add rax, rcx
    
    movzx rcx, byte [buffer + 34]
    imul rcx, 135
    add rax, rcx
    
    cmp rax, [target_6]
    setz bl
    and [exit_flag], bl

    mov rax, 1
    mov rdi, 1
    mov rsi, success_msg
    movzx rdx, byte [exit_flag]  
    imul rdx, success_len        
    syscall

    
    movzx rdi, byte [exit_flag]
    xor rdi, 1              
    mov rax, 60            
    syscall
