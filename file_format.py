#!/usr/bin/env python3

########## import ############

import json
import pyAesCrypt
import io
import pandas as pd
from sys import argv
import sqlalchemy as db
import pandas as pd
import os
from dotenv import load_dotenv

############### conf ##############

load_dotenv()
passwords_crypt = []
cache = open("cache.txt", "rb")
crypt = cache.read()
crypt = crypt.split(b"AES")
num = -1

#######################
if len(argv) != 2 or argv[1] == "-h":
    print("\n use ./file-format.py {FILE-TYPE}")
    exit()

name = os.getenv("PG_FILE_NAME")
type = argv[1]

for passwd in crypt:
    passwd = b"AES" + passwd
    passwords_crypt.append(passwd)

############################### CSV ########################
if type == "csv":
    dict = {'name': "Name", 'PW': passwords_crypt}
    df = pd.DataFrame(dict)
    df.to_csv(name + '.csv')

############################# JSON ##############################
elif type == "json":
    data = {}
    for passwd in passwords_crypt:
        num = num + 1
        x = str(passwd)
        y = "name"
        data[num] = {
            "passwd": x,
            "name": y,
        }
    with open(name + '.json', 'w') as f:
        json.dump(data, f, indent=4)

####################### SQL #############################
elif type == "sql":

    sql_type = os.getenv("PG_SQL_TYPE")
    sql_user = os.getenv("PG_SQL_USER")
    sql_passwd = os.getenv("PG_SQL_PASSWD")
    sql_ip = os.getenv("PG_SQL_IP")
    sql_table = os.getenv("PG_SQL_TABLE")

    engine = db.create_engine(sql_type+'://'+sql_user+':'+sql_passwd+'@'+sql_ip+'/'+sql_table)
    connection = engine.connect()
    metadata = db.MetaData()

    passwd = db.Table('passwd', metadata,
                      db.Column('id', db.Integer, autoincrement=True, primary_key=True),
                      db.Column('passid', db.String(255), nullable=False),
                      db.Column('passwd', db.LargeBinary(), nullable=False)
                      )
    metadata.create_all(engine)  # Creates the table

    for passwds in passwords_crypt:
        num = num + 1
        # Inserting record one by one
        query = db.insert(passwd).values(passid=num, passwd=passwds)
        ResultProxy = connection.execute(query)
        results = connection.execute(db.select([passwd])).fetchall()
        df = pd.DataFrame(results)
        df.columns = results[0].keys()
        df.head(4)
