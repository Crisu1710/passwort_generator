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

pools = lower + upper + num + symbols

# key = argv[1]
# length = int(argv[2])
# amount =


# passwords = []
passwords_crypt = []


# ------------ import and decrypt file ------------
def get(key):
    cache = open("cache.txt", "ab")
    passwords_decrypt = []
    bufferSize = 64 * 1024
    get_cache = open("cache.txt", "rb")
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
    return passwords_decrypt


# ------------ gen ------------
def gen(key, amount, length, pool):
    passwords_decrypt = get(key)
    passwords = []
    while len(
            passwords) < amount:  # as long as the existing passwords are less than the desired amount generate new one
        passwd = "".join(random.sample(pool, length))
        if passwd not in passwords and passwd not in passwords_decrypt:  # check if password is already created
            passwords.append(passwd)  # add password to array
        else:
            continue
    print(str(len(passwords)) + " passwords created")
    return passwords


# ------------ crypt ------------
def crypt(key, amount, length, pool):
    passwords = gen(key, amount, length, pool)
    bufferSize = 64 * 1024
    cache = open("cache.txt", "ab")
    for passwd in passwords:
        fCiph = io.BytesIO()
        fDec = io.BytesIO()
        pbdata = passwd.encode("utf-8")
        fIn = io.BytesIO(pbdata)
        pyAesCrypt.encryptStream(fIn, fCiph, key, bufferSize)
        crypt = fCiph.getvalue()
        cache.write(crypt)
    cache.close()


# print(passwords_crypt)
# print(passwords)

crypt(argv[1], int(argv[3]), int(argv[2]), pools)
