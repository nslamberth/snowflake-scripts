## Example Call to Snowflake SQL Rest API

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
from datetime import timedelta, timezone, datetime
import jwt
import requests
import pandas as pd

private_key_path = "" # generate a rsa private key and copy file path here
account = "" #  your account locator (to find: click your initials in lower left --> find your account --> click 'account details')
user = "" # your user name in all caps
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


## call sql api
query = "SELECT random() c1, random() c2, random() c3, random() c4 FROM TABLE(GENERATOR(ROWCOUNT => 10));"

response = requests.post(
    f'https://{account}.snowflakecomputing.com/api/v2/statements'
    , headers= {
        'Authorization': f'Bearer {token}'
        , 'X-Snowflake-Authorization-Token-Type': 'KEYPAIR_JWT'
        , 'Content-Type': 'application/json'
    }
    , json = {"statement": query}
)

# extract data and create dataframe
res_json = response.json()
col_names = [col['name'] for col in res_json['resultSetMetaData']['rowType']]
data = res_json['data']
df = pd.DataFrame(
    columns = col_names,
    data = data
)
print(df)

