#!/usr/bin/env python3

########## import ############
import pyAesCrypt
import io
from sys import argv

############### conf ##############
passwords_crypt = []
passwords_decrypt = []
bufferSize = 64 * 1024

# check if all parameters set correct
if len(argv) != 3 or argv[1] == "-h" or argv[2] == "-h":
    print(
        "\n use ./decrypt.py {KEY} and \n -a(ll) to show all passwds in encode text and decode \n use -q(uick) to only show passwds decoded \n use -n(um) to decoded a password by passwdid\n")
    exit()

key = argv[1]
mode = argv[2]
num = 0
pwid = 1
########## import and decrypt file #############

in_cache = open("cache.txt", "rb")
crypt = in_cache.read()
crypt = crypt.split(b"AES")  # split binary at AES (start) to get all encrypted passwords
for passwd in crypt:
    passwd = b"AES" + passwd  # add the AES back again, to get accepted value
    if mode == "-a":
        print(passwd)  # list all encrypted passwords if parameter is -a
        print("ID: " + str(
            num) + "  ^^^^------------------------------------------------------------------------------------------\n")
        num = num + 1
    if mode == "-q":
        try:  # decrypt all passwords with correct key (quick mode)
            passwords_crypt.append(passwd)
            fCiph = io.BytesIO(passwd)
            fDec = io.BytesIO()
            ctlen = len(passwd)
            fCiph.seek(0)
            pyAesCrypt.decryptStream(fCiph, fDec, key, bufferSize, ctlen)
            passwords_decrypt.append(str(pwid) + ": " + str(fDec.getvalue().decode("utf-8")))
            pwid = pwid + 1  # add a passwd ID
        finally:
            continue

if mode == "-a" or mode == "-n":  # decrypt all passwords with correct key (number mode)
    passid = input("ID: (max:"+str(num-1)+"): ") or num-1
    passwd = b"AES" + crypt[int(passid)]  # add the AES back again, to get accepted value
    fCiph = io.BytesIO(passwd)
    fDec = io.BytesIO()
    ctlen = len(passwd)
    fCiph.seek(0)
    pyAesCrypt.decryptStream(fCiph, fDec, key, bufferSize, ctlen)
    print("PASSWD ID:("+str(passid)+"):\n" + str(fDec.getvalue().decode("utf-8")))
else:
    if len(passwords_decrypt) == 0:
        print("wrong KEY")
    else:
        for passwd in passwords_decrypt:
            print(passwd)
