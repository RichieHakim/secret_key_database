"""
User level methods for the secret key database.
"""

from typing import Optional, Union
from pathlib import Path
import getpass

from . import database, encryption

def get_key_from_database(
    path_db: str,
    name: str,
    password: Optional[str] = None,
):
    """
    Retrieves an encrypted secret key from the database and decrypts it. \n
    RH 2024

    Args:
        path_db (str): 
            The path to the database file.
        name (str): 
            The name of the secret key to retrieve.
        password (str, optional): 
            The password to use for decryption. If not provided, the user will
            be prompted to enter it. Defaults to None.
    """
    ## Check types: str
    database._assert_type(path_db, str)
    database._assert_type(name, str)

    ## Check if the database exists
    if not Path(path_db).is_file():
        raise FileNotFoundError(f"Database file not found: {path_db}")

    ## Get the password from the user
    if password is None:
        password = getpass.getpass("Enter the password: ")
    database._assert_type(password, str)

    ## Retrieve the encrypted key from the database
    dict_encrypted_key = database.get_encrypted_key_from_database(
        path_db=path_db, 
        name=name,
    )

    ## Decrypt the secret key
    secret_key = encryption.decrypt_secret_key(
        password=password,
        **dict_encrypted_key,
    )

    return secret_key

def add_key_to_database(
    path_db: str,
    name: str,
    secret_key: Optional[Union[str, bytes]] = None,
    password: Optional[str] = None,
    metadata: Optional[str] = None,
    **kwargs_encrypt_secret_key
):
    """
    Adds a secret key to the database. \n
    RH 2024

    Args:
        path_db (str): 
            The path to the database file.
        name (str): 
            The name of the secret key.
        secret_key (Union[str, bytes]): 
            The secret key to add to the database. If not provided, the user
            will be prompted to enter it. Defaults to None.
        password (str, optional): 
            The password to use for encryption. If not provided, the user will
            be prompted to enter it. Defaults to None.
        metadata (str, optional): 
            Additional metadata about the encryption process. Defaults to None.
        **kwargs_encrypt_secret_key:
            Additional keyword arguments for the encryption process.
    """
    ## Check types: str
    database._assert_type(path_db, str)
    database._assert_type(name, str)
    if secret_key is not None:
        database._assert_type(secret_key, (str, bytes))
    if metadata is not None:
        database._assert_type(metadata, str)
    if password is not None:
        database._assert_type(password, str)

    ## Check if the database exists
    if not Path(path_db).is_file():
        raise FileNotFoundError(f"Database file not found: {path_db}")

    ## Get the secret key and password from the user
    if secret_key is None:
        secret_key = getpass.getpass("Enter the secret key: ")
    if password is None:
        password = getpass.getpass("Enter the password: ")

    ## Encrypt the secret key
    dict_encrypted_key = encryption.encrypt_secret_key(
        secret_key=secret_key, 
        password=password, 
        **kwargs_encrypt_secret_key,
    )

    ## Add the encrypted key to the database
    dict_encrypted_key['metadata'] = metadata
    database.append_encrypted_key_to_database(
        path_db=path_db, 
        name=name, 
        **dict_encrypted_key,
    )