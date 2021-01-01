#!/usr/bin/env python3

# ------------ import ------------
import random
from io import BytesIO
from sys import argv
import pyAesCrypt
import io

if len(argv) != 4:
    print("\n use old_main.py {KEY}\n int(password length) int(password amount) example: ./old_main.py savepw 4 2")
    exit()

# ------------ conf ------------
lower = "abcdefghijklmnopqrstuvwxyz"
upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
num = "0123456789"
symbols = "[]{}()#*~.:,;<>-_€§$&?+^"

pool = lower + upper + num + symbols

key = argv[1]
length = int(argv[2])
amount = int(argv[3])

bufferSize = 64 * 1024

passwords = []
passwords_crypt = []
passwords_decrypt = []

cache = open("cache.txt", "ab")
get_cache = open("cache.txt", "rb")

# ------------ import and decrypt file ------------
crypt = get_cache.read()
crypt = crypt.split(b"AES")
for passwd in crypt:
    passwd = b"AES" + passwd
    try:
        fCiph: BytesIO = io.BytesIO(passwd)
        fDec = io.BytesIO()
        ctlen = len(passwd)
        fCiph.seek(0)
        pyAesCrypt.decryptStream(fCiph, fDec, key, bufferSize, ctlen)
        passwords_decrypt.append(str(fDec.getvalue().decode("utf-8")))
    finally:
        continue
get_cache.close()

# ------------ gen ------------
while len(passwords) < amount:  # as long as the existing passwords are less than the desired amount generate new ones
    passwd = "".join(random.sample(pool, length))
    if passwd not in passwords and passwd not in passwords_decrypt:  # check if password is already created
        passwords.append(passwd)  # add password to array
    else:
        continue

# ------------ crypt ------------
for passwd in passwords:
    fCiph = io.BytesIO()
    fDec = io.BytesIO()
    pbdata = passwd.encode("utf-8")
    fIn = io.BytesIO(pbdata)
    pyAesCrypt.encryptStream(fIn, fCiph, key, bufferSize)
    crypt = fCiph.getvalue()
    cache.write(crypt)
    # passwords_crypt.append(crypt)
    # print(crypt)

cache.close()
print(str(len(passwords))+" passwords created")
# print(passwords_crypt)
# print(passwords)
