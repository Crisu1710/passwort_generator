#!/usr/bin/env python3

# ------------ import ------------
import random
from io import BytesIO
from sys import argv
import pyAesCrypt
import io
import os
from dotenv import load_dotenv
import sqlalchemy as db
import pandas as pd
import json

# ------------ conf ------------
components = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "numbers": "0123456789",
    "symbols": "[]{}()#*~.:;<>-_€§$&?+^"
}
pool = components["lower"] + components["upper"] + components["numbers"] + components["symbols"]

buffer_size = 64 * 1024
load_dotenv()

file = open("cache.txt", "a")
file.close()

do = argv[1]

if do == "con" and argv[2] == "sql":
    file_type = "sql"
else:
    file_type = ""

if os.getenv("PG_DECRYPT_TYPE") == "db" or file_type == "sql":  # set correct values in .env to use
    sql = {
        "type": os.getenv("PG_SQL_TYPE"),
        "user": os.getenv("PG_SQL_USER"),
        "passwd": os.getenv("PG_SQL_PASSWD"),
        "ip": os.getenv("PG_SQL_IP"),
        "table": os.getenv("PG_SQL_TABLE")
    }
    engine = db.create_engine(sql["type"] + '://' + sql["user"] + ':' + sql["passwd"] + '@' + sql["ip"] + '/' + sql["table"])
    connection = engine.connect()
else:
    db_connection = ""
    pass


# ------------ import and decrypt file ------------
def decrypt(key):
    passwords_decrypt = []  # set passwords_decrypt to null
    print("reading cache")
    if os.getenv("PG_DECRYPT_TYPE") == "db":  # get env PG_FILE_NAME (ste to "db" to decrypt the DB)
        df = pd.read_sql_table('passwd', connection)  # read table
        get_cache = df.passwd  # get all encrypted passwords from the DB
    else:
        get_cache = open("cache.txt", "rb")  # open the text file
        get_cache = get_cache.read()
        get_cache = get_cache.split(b"AES")  # split at b"AES" to find the start of one encrypted password
    for passwd in get_cache:
        if os.getenv("PG_DECRYPT_TYPE") != "db":
            passwd = b"AES" + passwd
        try:
            fCiph: BytesIO = io.BytesIO(passwd)
            fDec = io.BytesIO()
            ctlen = len(passwd)
            fCiph.seek(0)
            pyAesCrypt.decryptStream(fCiph, fDec, key, buffer_size, ctlen)
            passwords_decrypt.append(str(fDec.getvalue().decode("utf-8")))  # decrypt password and add it to array
        finally:
            continue
    return passwords_decrypt, get_cache


# ------------ gen ------------
def gen(key, amount, length):
    passwords_decrypt = decrypt(key)
    passwords = []
    while len(passwords) < amount:  # as long as the existing passwords are less than the desired amount generate new
        passwd = "".join(random.sample(pool, length))  # generate random password from pool
        if passwd not in passwords and passwd not in passwords_decrypt:  # check if password is already created
            passwords.append(passwd)  # add password to array "passwords" if not already created
        else:
            continue
    print(str(len(passwords)) + " passwords created")
    return passwords


# ------------ encrypt ------------
def crypt(key, amount, length):
    passwords = gen(key, amount, length)
    cache = open("cache.txt", "ab")
    print("encrypting ...")
    for passwd in passwords:
        fCiph = io.BytesIO()
        pbdata = passwd.encode("utf-8")
        fIn = io.BytesIO(pbdata)
        pyAesCrypt.encryptStream(fIn, fCiph, key, buffer_size)
        cryptpw = fCiph.getvalue()
        cache.write(cryptpw)
    cache.close()


# ------------ get/decrypt ------------
def get(key, mode):
    passwords, get_cache = decrypt(key)
    pwid = 1
    pw_num = 0
    if mode == "-q":
        for password in passwords:
            print(str(pwid) + ": " + password)
            pwid = pwid + 1
    elif mode == "-a":
        for crypt_pw, password in zip(get_cache, passwords):
            print(crypt_pw)
            print("ID: " + str(pw_num) + "  ^^^^------------------------------> " + password +
                  " <----------------------------------\n")
            pw_num = pw_num + 1


# ------------ converter ------------
def converter(filetype):
    passwords_decrypt, get_cache = decrypt("")
    name = os.getenv("PG_FILE_NAME")
    num = -1
    if filetype == "csv":  # convert to csv
        csv_dict = {'name': "Name", 'PW': get_cache}
        df = pd.DataFrame(csv_dict)
        df.to_csv(name + '.csv')

    # ------------ JSON ------------
    elif filetype == "json":  # convert to json
        data = {}
        for passwd in get_cache:
            num = num + 1
            x = str(passwd)
            y = "name"
            data[num] = {
                "passwd": x,
                "name": y,
            }
        with open(name + '.json', 'w') as f:
            json.dump(data, f, indent=4)

    # ------------ SQL ------------
    elif filetype == "sql":  # convert to sql set correct values in .env to use
        metadata = db.MetaData()
        passwd = db.Table('passwd', metadata,
                          db.Column('id', db.Integer, autoincrement=True, primary_key=True),
                          db.Column('passid', db.String(255), nullable=False),
                          db.Column('passwd', db.LargeBinary(), nullable=False)
                          )
        metadata.create_all(engine)  # Creates the table

        for passwds in get_cache:
            num = num + 1
            # Inserting record one by one
            query = db.insert(passwd).values(passid=num, passwd=passwds)
            ResultProxy = connection.execute(query)
            results = connection.execute(db.select([passwd])).fetchall()
            df = pd.DataFrame(results)
            df.columns = results[0].keys()
            df.head(4)


# ------------ MAIN ------------
if do == "gen":
    crypt(argv[2], int(argv[4]), int(argv[3]))
elif do == "get":
    get(argv[2], argv[3])
elif do == "con":
    converter(argv[2])
else:
    print("\n use main.py {gen|get|con} OPTION "
          "\n"
          "\n DO    Options: "
          "\n gen - {KEY} int(password length) int(password amount) > ./main.py pass123 15 4"
          "\n get - {KEY} {-a|-q}                                   > ./main.py pass123 -q"
          "\n con - {csv|json|sql}                                  > ./main.py json"
          "\n")
    exit()
