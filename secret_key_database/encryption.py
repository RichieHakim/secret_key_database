"""
This module contains an API for handling secret keys. It does the following:
    1. Encrypts secret keys using a password and a salt.
        a. The password is hashed using the PBKDF2 algorithm.
        b. The secret key is encrypted using the hashed password.
        c. The salt can either be generated or provided by the user.
        d. The resulting encrypted secret key and salt are stored in a file.
    2. Decrypts secret keys using a password and a salt.
        a. The password is hashed using the PBKDF2 algorithm.
        b. The encrypted secret key is decrypted using the hashed password.
        c. The salt is used to decrypt the secret key.
        d. The decrypted secret key is returned to the user as a plaintext
           string.
    3. Does basic database operations on the encrypted secret key and salt.
        a. Uses the sqlite3 module to create a database.
        b. Stores the encrypted secret key and salt in the database.
        c. Retrieves the encrypted secret key and salt from the database.
        d. Has fields for the encrypted secret key, salt, a unique identifier,
           timestamps, and other metadata about methods used to encrypt the
           secret key.
    4. Provides a command-line interface for encrypting and decrypting secret
       keys.
"""

import os
import datetime
from typing import Optional, Union

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


## Set default constants
class defaults:
    SALT_LENGTH = 16
    KEY_LENGTH = 32  ## Must be either: 128, 192, 256 bits (16, 24, 32 bytes / length)
    NONCE_LENGTH = 12
    ITERATIONS = 100000


def encrypt_secret_key(
    secret_key: str,
    password: str,
    salt: Optional[Union[str, bytes]] = None,
    nonce: Optional[Union[str, bytes]] = None,
    iterations: int = defaults.ITERATIONS,
    key_length: int = defaults.KEY_LENGTH,
    salt_length: int = defaults.SALT_LENGTH,
    nonce_length: int = defaults.NONCE_LENGTH,
    backend=default_backend(),
):
    """
    Encrypts a secret key using a password and a salt. \n
    RH 2024

    Args:
        secret_key (str): 
            The secret key to encrypt.
        password (str): 
            The password to use for encryption.
        salt (str, bytes, optional)
            The salt to use for encryption. If not provided, a random salt will be generated. Defaults to None.
        nonce (str, bytes, optional):
            The nonce to use for encryption. If not provided, a random nonce will be generated. Defaults to None.
        iterations (int, optional): 
            The number of iterations for the PBKDF2 algorithm. Defaults to constants.ITERATIONS.
        key_length (int, optional): 
            The length of the encryption key. Defaults to constants.KEY_LENGTH.
        salt_length (int, optional): 
            The length of the salt. Defaults to constants.SALT_LENGTH.
        nonce_length (int, optional):
            The length of the nonce for the GCM encryption. Defaults to constants.NONCE_LENGTH.
        backend ([type], optional): 
            The cryptography backend to use. Defaults to default_backend().
    
    Returns:
        (dict):
            A dictionary containing the following:\n
                * encrypted_key (bytes): The encrypted secret key.
                * salt (bytes): The salt used for encryption.
                * nonce (bytes): The nonce used for encryption.
                * algorithm (str): The algorithm used for encryption.
                * iterations (int): The number of iterations for the PBKDF2 algorithm.
                * key_length (int): The length of the encryption key.
                * timestamp (int): The timestamp of when the secret key was encrypted.
                * metadata (str): Additional metadata about the encryption process.
    """
    [_assert_type(var, str) for var in [secret_key, password]]  ## Check types: str
    _assert_type(salt, (str, bytes)) if salt is not None else None
    _assert_type(nonce, (str, bytes)) if nonce is not None else None
    [_assert_type(var, int) for var in [iterations, key_length, salt_length, nonce_length]]  ## Check types: int
    _assert_int_value(iterations, min_value=1, max_value=defaults.ITERATIONS*100)
    [_assert_int_value(var, min_value=1, max_value=1000) for var in [salt_length, nonce_length]]  ## Check values: 1 <= val <= 1000
    assert key_length in [16, 24, 32], "Invalid key length"  ## Check values: 16, 24, 32

    # Generate a random salt and nonce if they are not provided
    if salt is None:
        salt = os.urandom(salt_length)
    if nonce is None:
        nonce = os.urandom(nonce_length)

    # Derive a key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=backend,
    )
    key = kdf.derive(password.encode())

    # AES-GCM encryption: Galois/Counter Mode (GCM)
    aesgcm = AESGCM(key)
    encrypted_key = aesgcm.encrypt(nonce, secret_key.encode(), None)

    # Return the encrypted key, salt, and encryption parameters
    algorithm = "PBKDF2HMAC-SHA256, AES-GCM"
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "encrypted_key": encrypted_key,
        "salt": salt,
        "nonce": nonce,
        "iterations": iterations,
        "key_length": key_length,
        "algorithm": algorithm,
        "date": date,
    }


def decrypt_secret_key(
    password: str,
    encrypted_key: bytes,
    salt: bytes,
    nonce: bytes,
    iterations: int,
    key_length: int,
    backend=default_backend(),
    **kwargs
):
    """
    Decrypts a secret key using a password and a salt. \n
    RH 2024

    Args:
        password (str): 
            The password to use for decryption.
        encrypted_key (bytes): 
            The encrypted secret key.
        salt (bytes): 
            The salt used for encryption.
        nonce (bytes):
            The nonce used for encryption.
        iterations (int):
            The number of iterations for the PBKDF2 algorithm.
        key_length (int):
            The length of the encryption key.
        backend ([type], optional): 
            The cryptography backend to use. Defaults to default_backend().
        kwargs:
            Additional keyword arguments. The following are used: \n
                * algorithm (str): The algorithm used for encryption. If
                  provided, MUST be "PBKDF2HMAC-SHA256, AES-GCM".
    
    Returns:
        (str):
            The decrypted secret key.
    """
    if "algorithm" in kwargs:
        assert kwargs["algorithm"] == "PBKDF2HMAC-SHA256, AES-GCM", "Invalid algorithm"

    # Input validation
    [_assert_type(var, bytes) for var in [encrypted_key, nonce, salt]]  ## Check types: bytes
    [_assert_type(var, str) for var in [password]]  ## Check types: str
    _assert_int_value(iterations, min_value=1, max_value=defaults.ITERATIONS*100)
    assert key_length in [16, 24, 32], "Invalid key length"  ## Check values: 16, 24, 32

    # Derive a key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=backend,
    )

    key = kdf.derive(password.encode())

    aesgcm = AESGCM(key)
    try:
        decrypted_data = aesgcm.decrypt(nonce, encrypted_key, None)
        return decrypted_data.decode()
    except Exception as e:
        # Handle decryption failure (wrong password or data tampering)
        raise DecryptException("Decryption failed. Wrong password or data tampering.")


class DecryptException(Exception):
    pass


def _assert_type(value, expected_type):
    if not isinstance(value, expected_type):
        raise TypeError(f"{value} must be of type {expected_type}")
def _assert_int_value(value, min_value=None, max_value=None):
    if min_value is not None:
        if value < min_value:
            raise ValueError(f"{value} must be greater than or equal to {min_value}")
    if max_value is not None:
        if value > max_value:
            raise ValueError(f"{value} must be less than or equal to {max_value}")

