# six-seven-revenge CTF

A heap-based pwn challenge solution featuring off-by-one vulnerability exploitation 

## Challenge Description

This is a heap exploitation challenge from 0xfunCTF involving:
- 64-bit PIE binary with Full RELRO, Canary, and NX enabled
- glibc 2.42 (no __free_hook/__malloc_hook)
- Seccomp filtering blocking execve (ORW required)

## Vulnerability

Off-by-one null byte overflow in `edit_note()` function:
```c
read(0, notes[idx], sizes[idx]); 
notes[idx][retval] = '\0';  // Writes one byte past chunk!
```

## Exploitation Steps

1. **Poison null byte attack** - Clear PREV_IN_USE bit to trigger backward consolidation
2. **Chunk overlapping** - Create overlap to leak libc and heap addresses
3. **Tcache poisoning** - Bypass safe-linking with heap leak (glibc 2.42)
4. **Stack leak** - Read __environ pointer to get stack address
5. **ORW ROP chain** - open/read/write flag (no execve allowed by seccomp)

## Usage

```bash
# Local testing
python3 solve.py --local

# Remote exploitation
python3 solve.py
```

## Files

- `chall` - Challenge binary
- `solve.py` - Main exploit script (GLM-5 optimized)
- `exploit.py` - Alternative exploit approach
- `libc.so.6` - glibc 2.42 library
- `ld-linux-x86-64.so.2` - Dynamic linker
- `libseccomp.so.2` - Seccomp library
- `Dockerfile` - Container setup
- `summary.txt` - Detailed analysis

## Solution with GLM-5

This solution leverages GLM-5 advanced reasoning to:
- Analyze heap layout and chunk structures
- Identify optimal exploit primitives
- Calculate precise memory offsets
- Construct reliable ROP chains

## Target

```
nc chall.0xfun.org 62502
