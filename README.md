# passwort_generator

### Install

``` git clone git@github.com:Crisu1710/passwort_generator.git``` <br><br>
``` cd passwort_generator ``` <br><br>
``` pip install -r install.txt ```

### Use

``` 
use main.py {gen|get|con} OPTION

DO    Options:
gen - {KEY} int(password length) int(password amount) > ./main.py pass123 15 4
get - {KEY} {-a|-q}                                   > ./main.py pass123 -q
con - {csv|json|sql}                                  > ./main.py json"
```

### .env

```
ENV_NAME   DEFAULT_VALUE      DESCRIPTION

PG_SQL_TYPE=mysql      # SQL_Type
PG_SQL_PASSWD="****"   # SQL_Passwd
PG_SQL_IP="127.0.0.1"  # SQL_Server_IP
PG_SQL_USER=root       # SQL_User
PG_SQL_TABLE=passwd    # default table name
PG_FILE_NAME=output    # feilname for decrypt.py (CSV and JSON filename)
PG_DECRYPT_TYPE=file   # decrypt type set to <file> so cache.txt is being decrypted can be set to <db> to decrypt SQL Database
```
