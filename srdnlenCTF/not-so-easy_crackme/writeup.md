# not-so-easy crackme

CTF: Srdnlen CTF 2025 Finals
Category: rev
Difficulty: easy
Authors: @T0mm1 (Tommaso Casti)

## Description
Every CTF needs an easy crackme. Unfortunately this isn't so easy :(

## Overview
This rev challenge is composed by a stripped, statically linked ELF file for amd64.
When we run the file we see that it asks for the flag.
The program uses a self-modifying logic to hinder the player.

## Solution
If we open the file with GDB we can see the assembly and that after the first few instructions the code doesn't make sense.
The last instructions before the senseless ones implement a loop in which the program xor the bytes of the next instructions with some value.
We unterstand that we are looking at a self-modifying code.
```asm
Dump of assembler code from 0x401000 to 0x4010c8:
=> 0x0000000000401000:  mov    eax,0xa
   0x0000000000401005:  movabs rdi,0x401000
   0x000000000040100f:  mov    esi,0x10000
   0x0000000000401014:  mov    edx,0x7
   0x0000000000401019:  syscall
   0x000000000040101b:  movabs rax,0x1337deadbeef42
   0x0000000000401025:  movabs rsi,0x40103f
   0x000000000040102f:  mov    ecx,0x158
   0x0000000000401034:  xor    BYTE PTR [rsi],al
   0x0000000000401036:  inc    rsi
   0x0000000000401039:  ror    rax,0x8
   0x000000000040103d:  loop   0x401034
```

we can see the instructions after the xor loop with a break on 0x40103f

```asm
Dump of assembler code from 0x40103f to 0x4011cf:
=> 0x000000000040103f:  add    edi,DWORD PTR [rdi+0x41424344]
   0x0000000000401045:  xor    r15,0x41424344
   0x000000000040104c:  mov    BYTE PTR ds:0x402120,r15b
   0x0000000000401054:  not    BYTE PTR ds:0x402120
   0x000000000040105b:  mov    eax,0x1
   0x0000000000401060:  mov    edi,0x1
   0x0000000000401065:  movabs rsi,0x402000
   0x000000000040106f:  mov    edx,0x14
   0x0000000000401074:  syscall
   0x0000000000401076:  mov    rax,r15
   0x0000000000401079:  mov    rdi,rax
   0x000000000040107c:  lea    rsi,ds:0x402080
   0x0000000000401084:  mov    edx,0x3f
   0x0000000000401089:  syscall
   0x000000000040108b:  mov    rbx,rax
   0x000000000040108e:  dec    rbx
   0x0000000000401091:  cmp    BYTE PTR [rbx+0x402080],0xa
   0x0000000000401098:  jne    0x4010a3
   0x000000000040109a:  mov    BYTE PTR [rbx+0x402080],0x0
   0x00000000004010a1:  jmp    0x4010a6
   0x00000000004010a3:  mov    rbx,rax
   0x00000000004010a6:  cmp    rbx,0x23
   0x00000000004010aa:  sete   al
   0x00000000004010ad:  mov    BYTE PTR ds:0x402120,al
   0x00000000004010b4:  xor    rax,rax
   0x00000000004010b7:  movzx  rcx,BYTE PTR ds:0x402080
   0x00000000004010c0:  mov    rdx,rcx
   0x00000000004010c3:  shl    rdx,1
   0x00000000004010c6:  shr    rdx,1
   0x00000000004010c9:  add    rax,rdx
   0x00000000004010cc:  movzx  rcx,BYTE PTR ds:0x402081
   0x00000000004010d5:  mov    edx,0xc8
   0x00000000004010da:  sub    rdx,0x46
   0x00000000004010de:  imul   rcx,rdx
   0x00000000004010e2:  add    rax,rcx
   0x00000000004010e5:  movzx  rcx,BYTE PTR ds:0x402082
   0x00000000004010ee:  mov    edx,0x82
   0x00000000004010f3:  imul   rdx,rdx,0x82
   0x00000000004010fa:  imul   rcx,rdx
   0x00000000004010fe:  add    rax,rcx
   0x0000000000401101:  movzx  rcx,BYTE PTR ds:0x402083
   0x000000000040110a:  mov    rdx,QWORD PTR ds:0x40202e
   0x0000000000401112:  xor    rdx,rdx
   0x0000000000401115:  add    rdx,0x218608
   0x000000000040111c:  imul   rcx,rdx
   0x0000000000401120:  add    rax,rcx
   0x0000000000401123:  movzx  rcx,BYTE PTR ds:0x402084
   0x000000000040112c:  mov    edx,0x11061010
   0x0000000000401131:  mov    r8,rdx
   0x0000000000401134:  xor    rdx,0x12345
   0x000000000040113b:  xor    rdx,0x12345
   0x0000000000401142:  imul   rcx,rdx
   0x0000000000401146:  add    rax,rcx
   0x0000000000401149:  mov    rbx,QWORD PTR ds:0x402046
   0x0000000000401151:  cmp    rax,rbx
   0x0000000000401154:  sete   r8b
   0x0000000000401158:  and    BYTE PTR ds:0x402120,r8b
   0x0000000000401160:  mov    QWORD PTR ds:0x4020e0,rax
   0x0000000000401168:  mov    QWORD PTR ds:0x402121,rax
   0x0000000000401170:  movabs rsi,0x401197
   0x000000000040117a:  mov    ecx,0xe4
   0x000000000040117f:  mov    rdx,QWORD PTR ds:0x402121
   0x0000000000401187:  xor    BYTE PTR [rsi],dl
   0x0000000000401189:  inc    rsi
   0x000000000040118c:  ror    QWORD PTR ds:0x402121,0x8
   0x0000000000401195:  loop   0x40117f
```
We can see that the program takes the first 5 chars of our input, does some operations using some hardcoded numbers and then use the result to
decrypt the next part of itself. Before the loop we can see an instruction that compare the result with a number that is the right key to decrypt.
We can go block by block using the gdb and modifying rax in runtime to get the right code and see what the program does.
However, we prefer to script a code analyzer that directly prints all the assembly code:

```python
#!/usr/bin/env python3

"""
Step-by-step code extracter for self-modifying binary
Automatically skips decryption/XOR loops and forces critical comparisons to pass
"""

from libdebug import debugger
from capstone import *
import sys

def step_by_step_debug(binary_path):
    """
    Main debugging function that traces binary execution step by step
    Skips obfuscation loops and patches critical comparisons
    """
    
    # Initialize Capstone disassembler for x86-64
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    
    # Start the debugger
    d = debugger(binary_path)
    d.run()
    
    step_count = 0
    
    while True: 
        try:
            current_rip = d.regs.rip
            
            try:
                # Read and disassemble current instruction
                code = d.memory[current_rip:current_rip + 16]
                instructions = list(cs.disasm(code, current_rip, count=1))
                
                if instructions:
                    insn = instructions[0]
                    if insn.op_str:
                        instr_text = f"{insn.mnemonic} {insn.op_str}"
                    else:
                        instr_text = insn.mnemonic
                    
                    bytes_hex = " ".join([f"{b:02x}" for b in insn.bytes])

                    # Detect initial decryption loops: mov ecx/rcx with immediate value
                    # Only in early execution phase (before 0x401080)
                    
                    if ((insn.mnemonic == "mov" and 
                         ("ecx," in insn.op_str or "rcx," in insn.op_str)) and
                        "0x" in insn.op_str and
                        current_rip < 0x401080):
                        
                        loop_iterations = None
                        try:
                            # Extract loop iteration count from instruction
                            if "ecx, 0x" in insn.op_str:
                                hex_val = insn.op_str.split("ecx, 0x")[1]
                            elif "rcx, 0x" in insn.op_str:
                                hex_val = insn.op_str.split("rcx, 0x")[1]
                            else:
                                hex_val = insn.op_str.split("0x")[1]
                            
                            loop_iterations = int(hex_val, 16)
                        except:
                            loop_iterations = None
                        
                        # Skip significant decryption loops (> 10 iterations)
                        if loop_iterations and loop_iterations > 10:
                            
                            # Each iteration has 4 instructions (xor, inc, ror, loop)
                            instructions_per_iteration = 4
                            instructions_to_skip = loop_iterations * instructions_per_iteration
                            
                            # Execute the mov instruction and skip the entire loop
                            d.step()
                            step_count += 1
                            
                            for skip_i in range(instructions_to_skip):
                                try:
                                    d.step()
                                except Exception as e:
                                    print(e)
                                    break
                            
                            continue
                    
                    # Detect XOR loops: mov ecx with large value after initial phase
                    elif (insn.mnemonic == "mov" and "ecx," in insn.op_str and 
                          "0x" in insn.op_str and step_count > 60):
                        
                        try:
                            # Extract loop iteration count
                            hex_val = insn.op_str.split("ecx, 0x")[1]
                            loop_iterations = int(hex_val, 16)
                            
                            # Skip significant XOR loops (> 16 iterations)
                            if loop_iterations > 16:
                                print(f"0x{current_rip:08x} : {instr_text}")
                            
                                # Execute the mov instruction
                                d.step()
                                step_count += 1
                                
                                # Each XOR iteration has 5 instructions 
                                # (mov rdx, xor, inc rsi, ror, loop)
                                instructions_to_skip = loop_iterations * 5
                                
                                for skip_i in range(instructions_to_skip):
                                    try:
                                        d.step()
                                    except Exception as e:
                                        print(e)
                                        break
                                
                                continue
                        except:
                            pass
                    
                    # Print the current instruction address and mnemonic
                    print(f"0x{current_rip:08x} : {instr_text}")
                    
                    # Handle syscall instructions
                    if insn.mnemonic == "syscall":
                        rax = d.regs.rax
                        
                        # Intercept read syscalls (rax = 0) and provide fake input
                        if rax == 0:  
                            rsi = d.regs.rsi  # buffer address
                            rdx = d.regs.rdx  # buffer size
                            fake_input = b"A" * rdx  # fill with 'A' characters
                            d.memory[rsi:rsi + len(fake_input)] = fake_input
                            d.regs.rax = len(fake_input)  # return bytes read
                            d.regs.rip += 2  # skip syscall instruction
                            step_count += 1
                            continue
                    
                    # Handle critical comparison instructions
                    elif insn.mnemonic == "cmp" and "rax, rbx" in insn.op_str:
                        # These are the critical comparison addresses 
                        # where we need to force equality
                        critical_addresses = [0x401151, 0x401235, 0x401307, 
                                            0x4013e9, 0x40149b, 0x401545, 
                                            0x4015ef]
                        if current_rip in critical_addresses:
                            # Force RAX = RBX to make comparison pass
                            d.regs.rax = d.regs.rbx
                                     
            except Exception as e:
                print(e)
            
            try:
                d.step()
                step_count += 1
            except Exception as e:
                print(e)
                break
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(e)
            break
    
    try:
        d.kill()
    except:
        pass


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 advanced_step_debug.py <binary>")
        sys.exit(1)
    
    step_by_step_debug(sys.argv[1])


if __name__ == "__main__":
    main()
```

Now we can see all the code:

```
0x00401000 : mov eax, 0xa
0x00401005 : movabs rdi, 0x401000
0x0040100f : mov esi, 0x10000
0x00401014 : mov edx, 7
0x00401019 : syscall
0x0040101b : movabs rax, 0x1337deadbeef42
0x00401025 : movabs rsi, 0x40103f
0x0040103f : mov r15d, 0x41424344
0x00401045 : xor r15, 0x41424344
0x0040104c : mov byte ptr [0x402120], r15b
0x00401054 : not byte ptr [0x402120]
0x0040105b : mov eax, 1
0x00401060 : mov edi, 1
0x00401065 : movabs rsi, 0x402000
0x0040106f : mov edx, 0x14
0x00401074 : syscall
0x00401076 : mov rax, r15
0x00401079 : mov rdi, rax
0x0040107c : lea rsi, [0x402080]
0x00401084 : mov edx, 0x3f
0x00401089 : syscall
0x0040108b : mov rbx, rax
0x0040108e : dec rbx
0x00401091 : cmp byte ptr [rbx + 0x402080], 0xa
0x00401098 : jne 0x4010a3
0x004010a3 : mov rbx, rax
0x004010a6 : cmp rbx, 0x23
0x004010aa : sete al
0x004010ad : mov byte ptr [0x402120], al
0x004010b4 : xor rax, rax
0x004010b7 : movzx rcx, byte ptr [0x402080]
0x004010c0 : mov rdx, rcx
0x004010c3 : shl rdx, 1
0x004010c6 : shr rdx, 1
0x004010c9 : add rax, rdx
0x004010cc : movzx rcx, byte ptr [0x402081]
0x004010d5 : mov edx, 0xc8
0x004010da : sub rdx, 0x46
0x004010de : imul rcx, rdx
0x004010e2 : add rax, rcx
0x004010e5 : movzx rcx, byte ptr [0x402082]
0x004010ee : mov edx, 0x82
0x004010f3 : imul rdx, rdx, 0x82
0x004010fa : imul rcx, rdx
0x004010fe : add rax, rcx
0x00401101 : movzx rcx, byte ptr [0x402083]
0x0040110a : mov rdx, qword ptr [0x40202e]
0x00401112 : xor rdx, rdx
0x00401115 : add rdx, 0x218608
0x0040111c : imul rcx, rdx
0x00401120 : add rax, rcx
0x00401123 : movzx rcx, byte ptr [0x402084]
0x0040112c : mov edx, 0x11061010
0x00401131 : mov r8, rdx
0x00401134 : xor rdx, 0x12345
0x0040113b : xor rdx, 0x12345
0x00401142 : imul rcx, rdx
0x00401146 : add rax, rcx
0x00401149 : mov rbx, qword ptr [0x402046]
0x00401151 : cmp rax, rbx
0x00401154 : sete r8b
0x00401158 : and byte ptr [0x402120], r8b
0x00401160 : mov qword ptr [0x4020e0], rax
0x00401168 : mov qword ptr [0x402121], rax
0x00401170 : movabs rsi, 0x401197
0x0040117a : mov ecx, 0xe4
0x00401197 : xor rax, rax
0x0040119a : movzx rcx, byte ptr [0x402085]
0x004011a3 : mov edx, 0x86
0x004011a8 : imul rdx, rdx, 0x86
0x004011af : mov r8, rdx
0x004011b2 : add r8, 0x64
0x004011b6 : sub r8, 0x64
0x004011ba : imul rcx, r8
0x004011be : add rax, rcx
0x004011c1 : movzx rcx, byte ptr [0x402086]
0x004011ca : mov r8d, 0x1337b510
0x004011d0 : mov r9, r8
0x004011d3 : not r9
0x004011d6 : not r9
0x004011d9 : imul rcx, r9
0x004011dd : add rax, rcx
0x004011e0 : movzx rcx, byte ptr [0x402087]
0x004011e9 : mov r9d, 0x24b6d8
0x004011ef : mov r10, r9
0x004011f2 : xor r9, r10
0x004011f5 : add r9, r10
0x004011f8 : imul rcx, r9
0x004011fc : add rax, rcx
0x004011ff : movzx rcx, byte ptr [0x402088]
0x00401208 : lea rdx, [rcx]
0x0040120b : add rax, rdx
0x0040120e : movzx r11, byte ptr [0x402089]
0x00401217 : mov r12d, 0x86
0x0040121d : mov r13, r11
0x00401220 : bswap r13
0x00401223 : bswap r13
0x00401226 : imul r13, r12
0x0040122a : add rax, r13
0x0040122d : mov rbx, qword ptr [0x40204e]
0x00401235 : cmp rax, rbx
0x00401238 : sete r8b
0x0040123c : and byte ptr [0x402120], r8b
0x00401244 : mov qword ptr [0x4020e8], rax
0x0040124c : mov qword ptr [0x402121], rax
0x00401254 : movabs rsi, 0x40127b
0x0040125e : mov ecx, 0xd2
0x0040127b : xor rax, rax
0x0040127e : movzx rcx, byte ptr [0x40208a]
0x00401287 : mov r8d, 0x14ff4ba1
0x0040128d : push r8
0x0040128f : pop rdx
0x00401290 : imul rcx, rdx
0x00401294 : add rax, rcx
0x00401297 : movzx rcx, byte ptr [0x40208b]
0x004012a0 : mov edx, 0x4951
0x004012a5 : mov r8, rdx
0x004012a8 : shl r8, 1
0x004012ab : shr r8, 1
0x004012ae : imul rcx, r8
0x004012b2 : add rax, rcx
0x004012b5 : movzx rcx, byte ptr [0x40208c]
0x004012be : mov edx, 0x89
0x004012c3 : and rdx, 0xffff
0x004012ca : imul rcx, rdx
0x004012ce : add rax, rcx
0x004012d1 : movzx rcx, byte ptr [0x40208d]
0x004012da : add rax, rcx
0x004012dd : movzx rcx, byte ptr [0x40208e]
0x004012e6 : mov rdx, qword ptr [0x4020e0]
0x004012ee : xor rdx, rdx
0x004012f1 : add rdx, 0x273c59
0x004012f8 : imul rcx, rdx
0x004012fc : add rax, rcx
0x004012ff : mov rbx, qword ptr [0x402056]
0x00401307 : cmp rax, rbx
0x0040130a : sete r8b
0x0040130e : and byte ptr [0x402120], r8b
0x00401316 : mov qword ptr [0x4020f0], rax
0x0040131e : mov qword ptr [0x402121], rax
0x00401326 : movabs rsi, 0x40134d
0x00401330 : mov ecx, 0xe2
0x0040134d : xor rax, rax
0x00401350 : mov r8, qword ptr [0x40202e]
0x00401358 : add r8, qword ptr [0x402036]
0x00401360 : movzx rcx, byte ptr [0x40208f]
0x00401369 : mov r9d, 0x118db651
0x0040136f : imul rcx, r9
0x00401373 : add rax, rcx
0x00401376 : movzx rcx, byte ptr [0x402090]
0x0040137f : mov edx, 0x4309
0x00401384 : lea r9, [rdx]
0x00401387 : imul rcx, r9
0x0040138b : add rax, rcx
0x0040138e : movzx rcx, byte ptr [0x402091]
0x00401397 : mov edx, 1
0x0040139c : imul rcx, rdx
0x004013a0 : add rax, rcx
0x004013a3 : movzx rcx, byte ptr [0x402092]
0x004013ac : mov edx, 0x83
0x004013b1 : mov r9, qword ptr [0x4020e8]
0x004013b9 : xor r9, r9
0x004013bc : add rdx, r9
0x004013bf : imul rcx, rdx
0x004013c3 : add rax, rcx
0x004013c6 : movzx rcx, byte ptr [0x402093]
0x004013cf : mov edx, 0x224d9b
0x004013d4 : rol rdx, 1
0x004013d7 : ror rdx, 1
0x004013da : imul rcx, rdx
0x004013de : add rax, rcx
0x004013e1 : mov rbx, qword ptr [0x40205e]
0x004013e9 : cmp rax, rbx
0x004013ec : sete r8b
0x004013f0 : and byte ptr [0x402120], r8b
0x004013f8 : mov qword ptr [0x4020f8], rax
0x00401400 : mov qword ptr [0x402121], rax
0x00401408 : movabs rsi, 0x40142f
0x00401412 : mov ecx, 0xaa
0x0040142f : xor rax, rax
0x00401432 : movzx rcx, byte ptr [0x402094]
0x0040143b : mov edx, 0x2819e8
0x00401440 : imul rcx, rdx
0x00401444 : add rax, rcx
0x00401447 : movzx rcx, byte ptr [0x402095]
0x00401450 : add rax, rcx
0x00401453 : movzx rcx, byte ptr [0x402096]
0x0040145c : mov edx, 0x4a64
0x00401461 : imul rcx, rdx
0x00401465 : add rax, rcx
0x00401468 : movzx rcx, byte ptr [0x402097]
0x00401471 : mov edx, 0x8a
0x00401476 : imul rcx, rdx
0x0040147a : add rax, rcx
0x0040147d : movzx rcx, byte ptr [0x402098]
0x00401486 : mov r8d, 0x159df710
0x0040148c : imul rcx, r8
0x00401490 : add rax, rcx
0x00401493 : mov rbx, qword ptr [0x402066]
0x0040149b : cmp rax, rbx
0x0040149e : sete r8b
0x004014a2 : and byte ptr [0x402120], r8b
0x004014aa : mov qword ptr [0x402121], rax
0x004014b2 : movabs rsi, 0x4014d9
0x004014bc : mov ecx, 0xaa
0x004014d9 : xor rax, rax
0x004014dc : movzx rcx, byte ptr [0x402099]
0x004014e5 : mov edx, 0x23e5fd
0x004014ea : imul rcx, rdx
0x004014ee : add rax, rcx
0x004014f1 : movzx rcx, byte ptr [0x40209a]
0x004014fa : add rax, rcx
0x004014fd : movzx rcx, byte ptr [0x40209b]
0x00401506 : mov edx, 0x4519
0x0040150b : imul rcx, rdx
0x0040150f : add rax, rcx
0x00401512 : movzx rcx, byte ptr [0x40209c]
0x0040151b : mov r8d, 0x12a67c71
0x00401521 : imul rcx, r8
0x00401525 : add rax, rcx
0x00401528 : movzx rcx, byte ptr [0x40209d]
0x00401531 : mov edx, 0x85
0x00401536 : imul rcx, rdx
0x0040153a : add rax, rcx
0x0040153d : mov rbx, qword ptr [0x40206e]
0x00401545 : cmp rax, rbx
0x00401548 : sete r8b
0x0040154c : and byte ptr [0x402120], r8b
0x00401554 : mov qword ptr [0x402121], rax
0x0040155c : movabs rsi, 0x401583
0x00401566 : mov ecx, 0x7b
0x00401583 : xor rax, rax
0x00401586 : movzx rcx, byte ptr [0x40209e]
0x0040158f : mov edx, 0x4731
0x00401594 : imul rcx, rdx
0x00401598 : add rax, rcx
0x0040159b : movzx rcx, byte ptr [0x40209f]
0x004015a4 : add rax, rcx
0x004015a7 : movzx rcx, byte ptr [0x4020a0]
0x004015b0 : mov edx, 0x258ad7
0x004015b5 : imul rcx, rdx
0x004015b9 : add rax, rcx
0x004015bc : movzx rcx, byte ptr [0x4020a1]
0x004015c5 : mov r8d, 0x13cc3761
0x004015cb : imul rcx, r8
0x004015cf : add rax, rcx
0x004015d2 : movzx rcx, byte ptr [0x4020a2]
0x004015db : mov edx, 0x87
0x004015e0 : imul rcx, rdx
0x004015e4 : add rax, rcx
0x004015e7 : mov rbx, qword ptr [0x402076]
0x004015ef : cmp rax, rbx
0x004015f2 : sete r8b
0x004015f6 : and byte ptr [0x402120], r8b
0x004015fe : mov eax, 1
0x00401603 : mov edi, 1
0x00401608 : movabs rsi, 0x402016
0x00401612 : movzx rdx, byte ptr [0x402120]
0x0040161b : imul rdx, rdx, 0x16
0x0040161f : syscall
0x00401621 : movzx rdi, byte ptr [0x402120]
0x0040162a : xor rdi, 1
0x0040162e : mov eax, 0x3c
0x00401633 : syscall
```

## Exploit

We analyze it and see that we have 7 blocks. Each block works with 5 chars, shuffles them and calculates sum([input[y+i]*(x**i) for i in range(5)])
where x is a different value for each block and y is the block number. We can recover x and the shuffle looking at the assembly.
We can recover the chars writing each key in base x and reversing the shuffle:

```python
def shift_vals(vals, base):
    aux_vals = [0, 0, 0, 0, 0]
    if base == 130:
        shift_array = [0, 1, 2, 3, 4]
    elif base == 134:
        shift_array = [3, 4, 0, 2, 1]
    elif base == 137:
        shift_array = [3, 2, 1, 4, 0]
    elif base == 131:
        shift_array = [2, 3, 1, 4, 0]
    elif base == 138:
        shift_array = [1, 3, 2, 0, 4]
    elif base == 133:
        shift_array = [1, 4, 2, 0, 3]
    else:
        shift_array = [1, 4, 0, 2, 3]
    for i in range(5):
        aux_vals[shift_array[i]] = vals[i]
    return aux_vals

def to_base(num, base):
    vals = []
    while num > 0:
        remainder = num % base
        vals.append(remainder)
        num = num // base
    vals = shift_vals(vals, base)
    chars = ""
    for x in vals:
        chars += chr(x)
    return chars

blocks_chars_enc = [31089254935, 35763743827, 42223415940, 28191960307,
                    18996768081, 29981803211, 11129167848]
bases = [130, 134, 137, 131, 138, 133, 135]
flag = ""

for i in range(len(blocks_chars_enc)):
    flag += to_base(blocks_chars_enc[i], bases[i])

print(flag)
```

This will print the flag: 
*srdnlen{W0w_y0u_4r3_4c7u4lly_G00D!}*
