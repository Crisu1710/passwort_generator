# passwort_generator

### Install

``` git clone git@github.com:Crisu1710/passwort_generator.git``` <br><br>
``` cd passwort_generator ``` <br><br>
``` pip install -r install.txt ```

### Use

``` ./gen.py <KEY> <PASSWORD_LENGTH> <PASSWORD_AMOUNT> ``` <br><br>
``` ./file_format.py <TYPE> ``` Copies the data in cache.txt to one of these fromates and save them <br>

TYPES: <br>
sql <br>
csv <br>
json <br>

``` ./decrypt.py <KEY> <PARAMETER> ``` <br>

PARAMETERS <br>
-a(ll) to show all passwds in encoded text and decode <br>
-q(uick) to only show passwds decoded <br>
-n(um) to decode a password by password_ID

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
