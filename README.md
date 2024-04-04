# secret_key_database
This is a very simple library to encrypt and store secret keys (or any text)
locally. <br>
The keys are stored in a local sqlite database. The keys are encrypted using
AES-GCM. That's it. In theory, the database file can be shared publicly since
the keys are encrypted and require a password to decrypt, but it's best to keep
it private. <br>
This approach works great when:
- Number of keys is small
- The keys are not very sensitive (e.g. low risk API keys)
- You store the database in a semi-secure location (computer with a password,
  private repository, etc.)
- You don't want to use an external or cloud service as a key/password manager
- You need a simple API to store and retrieve keys

## Installation
```
pip install secret_key_database
```

from source:
```
git clone https://github.com/RichieHakim/secret_key_database
cd secret_key_database
pip install -e .
```

## Demo
```
import secret_key_database as skd

# Create a new database
path_db = 'path/to/database.db'
db = skd.database.create_database(path_db)

# Add a new key
skd.database.append_encrypted_key_to_database(
    path_db=path_db,
    name='key_name',
)

# Get a key
key = skd.database.get_decrypted_key_from_database(
    path_db=path_db,
    name='key_name',
)
```