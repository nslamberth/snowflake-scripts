## Example API Call to Cortex Analyst
## Modified version of script at this page:
## https://docs.snowflake.com/en/developer-guide/sql-api/authenticating#python-example

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.backends import default_backend
import base64
from getpass import getpass
import hashlib
from datetime import timedelta, timezone, datetime
import jwt
import requests
import pprint

private_key_path = "" # generate a rsa private key and copy file path here
account = "" #  your account locator (to find: click your initials in lower left --> find your account --> click 'account details')
user = "" # your user name in all caps
semantic_model_file_path = "" # replace with semantic model path from snowflake (should start with an @)
qualified_username = account + "." + user

# Open the private key file.
private_key = None
with open(private_key_path, 'rb') as pem_in:
    pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())

# generate public key hash
public_key_raw = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
sha256hash = hashlib.sha256()
sha256hash.update(public_key_raw)
public_key_fp = 'SHA256:' + base64.b64encode(sha256hash.digest()).decode('utf-8')

# create jwt payload
now = datetime.now(timezone.utc)
lifetime = timedelta(minutes=59)
payload = {
    "iss": qualified_username + '.' + public_key_fp,
    "sub": qualified_username,
    "iat": now,
    "exp": now + lifetime
}

# create jwt token
encoding_algorithm="RS256"
token = jwt.encode(payload, key=private_key, algorithm=encoding_algorithm)
if isinstance(token, bytes):
  token = token.decode('utf-8')

## call api
response = requests.post(
    f'https://{account}.snowflakecomputing.com/api/v2/cortex/analyst/message'
    , headers= {
        'Authorization': f'Bearer {token}'
        , 'X-Snowflake-Authorization-Token-Type': 'KEYPAIR_JWT'
        , 'Content-Type': 'application/json'
    }
    , json = {
    "messages": [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "what date range does the data cover?"
                }
            ]
        }
    ],
    "semantic_model_file": semantic_model_file_path
    })

res_json = response.json()
print(''.join(res_json['message']['content'][0]['text']))
print('\nSQL QUERY:\n')
print(res_json['message']['content'][1]['statement'])
