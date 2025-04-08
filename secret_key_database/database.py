from typing import Optional
import sqlite3
import uuid

from .encryption import _assert_type, _assert_int_value, defaults

KEYS_DATABASE = {
    "name": 'TEXT PRIMARY KEY',
    "id": 'TEXT NOT NULL UNIQUE',
    "encrypted_key": 'BLOB NOT NULL UNIQUE',
    "salt": 'BLOB NOT NULL UNIQUE',
    "nonce": 'BLOB NOT NULL UNIQUE',
    "algorithm": 'TEXT NOT NULL',
    "iterations": 'INTEGER NOT NULL',
    "key_length": 'INTEGER NOT NULL',
    "date": 'TEXT NOT NULL',
    "version": 'TEXT NOT NULL',
    "metadata": 'TEXT',
}


def create_database(path_db: str):
    """
    Creates a new SQLite database for storing encrypted secret keys. \n
    RH 2024

    Args:
        path_db (str): 
            The path to the database file.
    """
    _assert_type(path_db, str)  ## Check types: str

    # Create the database schema
    with sqlite3.connect(path_db) as conn:
        conn.execute(
            f"""CREATE TABLE encrypted_keys (
                {', '.join([f'{key} {value}' for key, value in KEYS_DATABASE.items()])}
            )"""
        )


def append_encrypted_key_to_database(
    path_db: str,
    name: str,
    encrypted_key: bytes,
    salt: bytes,
    nonce: bytes,
    algorithm: str,
    iterations: int,
    key_length: int,
    date: Optional[str] = None,
    version: Optional[str] = None,
    metadata: Optional[str] = None,
):
    """
    Inserts an encrypted key into an SQLite database. \n
    RH 2024

    Args:
        path_db (str): 
            The path to the database file.
        name (str): 
            The name of the encrypted key.
        encrypted_key (bytes): 
            The encrypted secret key.
        salt (bytes): 
            The salt used for encryption.
        nonce (bytes):
            The nonce used for encryption.
        algorithm (str): 
            The algorithm used for encryption.
        iterations (int): 
            The number of iterations for the PBKDF2 algorithm.
        key_length (int): 
            The length of the encryption key.
        date (str, optional):
            The date of the encryption. Defaults to None.
        version (str, optional):
            The version of secret_key_database. Defaults to None and gathered from defaults.
        metadata (str, optional): 
            Additional metadata about the encryption process. Defaults to None.
    """
    _assert_type(path_db, str)  ## Check types: str
    _assert_type(name, str)  ## Check types: str
    [_assert_type(var, bytes) for var in [encrypted_key, salt, nonce]]  ## Check types: bytes
    _assert_type(algorithm, str)  ## Check types: str
    [_assert_int_value(var, min_value=0, max_value=defaults.ITERATIONS*100) for var in [iterations, key_length]]  ## Check values: 0 <= val <= 1000
    _assert_type(date, str) if date is not None else None
    _assert_type(version, str) if version is not None else None
    _assert_type(metadata, str) if metadata is not None else None
    
    # Create a unique ID for the encrypted key
    id = str(uuid.uuid4())

    data = {
        "name": name,
        "id": id,
        "encrypted_key": encrypted_key,
        "salt": salt,
        "nonce": nonce,
        "algorithm": algorithm,
        "iterations": iterations,
        "key_length": key_length,
        "date": date,
        "version": version,
        "metadata": metadata,
    }
    command = f"INSERT INTO encrypted_keys ({', '.join(KEYS_DATABASE.keys())}) VALUES ({', '.join(['?']*len(KEYS_DATABASE.keys()))})"

    # Insert the encrypted key into the database
    with sqlite3.connect(path_db) as conn:
        conn.execute(
            command,
            tuple(data.values()),
        )


def get_encrypted_key_from_database(
    path_db: str, 
    name: Optional[str] = None,
    id: Optional[str] = None,
):
    """
    Retrieves an encrypted key from a SQLite database. \n
    RH 2024

    Args:
        path_db (str): 
            The path to the database file.
        name (str, optional): 
            The name of the encrypted key. Must be provided if ID is not
            provided. Defaults to None.
        id (str, optional): 
            The unique ID of the encrypted key. Must be provided if name is not
            provided. Supersedes name if both are provided. Defaults to None.

    Returns:
        (dict):
            A dictionary containing the following:\n
                * name (str): The name of the encrypted key.
                * id (str): The unique ID of the encrypted key.
                * encrypted_key (bytes): The encrypted secret key.
                * salt (bytes): The salt used for encryption.
                * nonce (bytes): The nonce used for encryption.
                * algorithm (str): The algorithm used for encryption.
                * iterations (int): The number of iterations for the PBKDF2 algorithm.
                * key_length (int): The length of the encryption key.
                * date (str): The date of the encryption.
                * metadata (str): Additional metadata about the encryption process.
    """
    _assert_type(path_db, str)  ## Check types: str
    if name is not None:
        _assert_type(name, str)
    if id is not None:
        _assert_type(id, str)

    # Query the database for the encrypted key
    with sqlite3.connect(path_db) as conn:
        if id is not None:
            query = f"SELECT * FROM encrypted_keys WHERE id = '{id}'"
        elif name is not None:
            query = f"SELECT * FROM encrypted_keys WHERE name = '{name}'"
        else:
            raise ValueError("Either name or ID must be provided")

        result = conn.execute(query).fetchone()
        if result is None:
            raise ValueError("Encrypted key not found in database")

        return dict(zip(KEYS_DATABASE.keys(), result))
    

def get_all_data_from_database(path_db: str):
    """
    Retrieves all encrypted keys from a SQLite database. \n
    RH 2024

    Args:
        path_db (str): 
            The path to the database file.

    Returns:
        (list):
            A list of dictionaries, each containing the following:\n
                * name (str): The name of the encrypted key.
                * id (str): The unique ID of the encrypted key.
                * encrypted_key (bytes): The encrypted secret key.
                * salt (bytes): The salt used for encryption.
                * nonce (bytes): The nonce used for encryption.
                * algorithm (str): The algorithm used for encryption.
                * iterations (int): The number of iterations for the PBKDF2 algorithm.
                * key_length (int): The length of the encryption key.
                * date (str): The date of the encryption.
                * metadata (str): Additional metadata about the encryption process.
    """
    _assert_type(path_db, str)  ## Check types: str

    # Query the database for all encrypted keys
    with sqlite3.connect(path_db) as conn:
        query = "SELECT * FROM encrypted_keys"
        results = conn.execute(query).fetchall()
        return [dict(zip(KEYS_DATABASE.keys(), result)) for result in results]
    
def get_names_from_database(path_db: str):
    """
    Retrieves all names from a SQLite database. \n
    RH 2024

    Args:
        path_db (str): 
            The path to the database file.

    Returns:
        (list):
            A list of names of the encrypted keys in the database.
    """
    _assert_type(path_db, str)  ## Check types: str

    # Query the database for all names
    with sqlite3.connect(path_db) as conn:
        query = "SELECT name FROM encrypted_keys"
        results = conn.execute(query).fetchall()
        return [result[0] for result in results]
    

def delete_encrypted_key_from_database(
    path_db: str, 
    name: Optional[str] = None,
    id: Optional[str] = None,
):
    """
    Deletes an encrypted key from a SQLite database. \n
    RH 2024

    Args:
        path_db (str): 
            The path to the database file.
        name (str, optional): 
            The name of the encrypted key. Must be provided if ID is not
            provided. Defaults to None.
        id (str, optional): 
            The unique ID of the encrypted key. Must be provided if name is not
            provided. Supersedes name if both are provided. Defaults to None.
    """
    _assert_type(path_db, str)  ## Check types: str
    if name is not None:
        _assert_type(name, str)
    if id is not None:
        _assert_type(id, str)

    # Delete the encrypted key from the database
    with sqlite3.connect(path_db) as conn:
        if id is not None:
            query = f"DELETE FROM encrypted_keys WHERE id = '{id}'"
        elif name is not None:
            query = f"DELETE FROM encrypted_keys WHERE name = '{name}'"
        else:
            raise ValueError("Either name or ID must be provided")

        conn.execute(query)


def join_databases(path_db1: str, path_db2: str):
    """
    Joins two SQLite databases into a single database. \n
    RH 2024

    Args:
        path_db1 (str): 
            The path to the first database file. This database will be
            modified to include the contents of the second database.
        path_db2 (str):
            The path to the second database file. This database will not be
            modified. Its contents will be copied to the first database.
    """
    _assert_type(path_db1, str)  ## Check types: str
    _assert_type(path_db2, str)  ## Check types: str

    # Get all data from the second database
    data = get_all_data_from_database(path_db2)

    # Append the data to the first database
    with sqlite3.connect(path_db1) as conn:
        for row in data:
            conn.execute(
                f"INSERT INTO encrypted_keys ({', '.join(KEYS_DATABASE.keys())}) VALUES ({', '.join(['?']*len(KEYS_DATABASE.keys()))})",
                tuple(row.values()),
            )
