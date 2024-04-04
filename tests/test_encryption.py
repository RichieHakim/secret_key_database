import os
import itertools

import pytest
from hypothesis import given, strategies as st, settings

from secret_key_database.encryption import encrypt_secret_key, decrypt_secret_key, defaults, DecryptException


#####################################
### unit test: encrypt_secret_key ###
#####################################

# Test Output Structure
def test_encrypt_secret_key_output_structure():
    secret_key = 'test_secret'
    password = 'test_password'
    result = encrypt_secret_key(secret_key, password)
    assert isinstance(result, dict), "Output should be a dictionary"
    expected_keys = ["encrypted_key", "salt", "nonce", "iterations", "key_length", "algorithm", "date"]
    assert all(key in result for key in expected_keys), "All expected keys should be in the output dictionary"
    assert isinstance(result['encrypted_key'], bytes), "Encrypted key should be bytes"
    assert isinstance(result['salt'], bytes), "Salt should be bytes"
    assert isinstance(result['nonce'], bytes), "Nonce should be bytes"
    assert isinstance(result['iterations'], int), "Iterations should be an integer"
    assert isinstance(result['key_length'], int), "Key length should be an integer"
    assert isinstance(result['algorithm'], str), "Algorithm should be a string"
    assert isinstance(result['date'], str), "Date should be a string"

# Test Default Values
def test_encrypt_secret_key_with_provided_salt_and_nonce():
    secret_key = 'test_secret'
    password = 'test_password'
    salt = b'salt' * 4  # 16 bytes
    nonce = b'nonce' * 3  # 12 bytes
    result = encrypt_secret_key(secret_key, password, salt=salt, nonce=nonce)
    assert result['salt'] == salt, "Provided salt should be used"
    assert result['nonce'] == nonce, "Provided nonce should be used"

# Test Correctness of Encryption
@given(secret_key=st.text(min_size=1, max_size=100), password=st.text(min_size=1, max_size=100),)
@settings(max_examples=100)
def test_encrypt_secret_key_encryption_correctness(secret_key, password):
    result = encrypt_secret_key(secret_key, password)
    assert result['encrypted_key'] != secret_key.encode(), "The secret key should be encrypted"

# Test with Different Iterations
def test_encrypt_secret_key_parameters_impact():
    secret_key = 'test_secret'
    password = 'test_password'
    # Test with different iterations
    result_low_iter = encrypt_secret_key(secret_key, password, iterations=10)
    result_high_iter = encrypt_secret_key(secret_key, password, iterations=1000000)
    assert result_low_iter['encrypted_key'] != result_high_iter['encrypted_key'], "Different iterations should result in different encrypted keys"

# Test Invalid `secret_key` and `password` Types
@given(st.one_of(st.integers(), st.lists(st.text()), st.dictionaries(keys=st.text(), values=st.integers())))
def test_encrypt_secret_key_invalid_secret_key_and_password_types(invalid_input):
    with pytest.raises(TypeError):
        encrypt_secret_key(secret_key=invalid_input, password="valid_password")
    with pytest.raises(TypeError):
        encrypt_secret_key(secret_key="valid_secret", password=invalid_input)

# Test Invalid `salt` and `nonce` Types
@given(st.one_of(st.integers(), st.lists(st.binary()), st.dictionaries(keys=st.text(), values=st.integers())))
def test_encrypt_secret_key_invalid_salt_and_nonce_types(invalid_input):
    with pytest.raises(TypeError):
        encrypt_secret_key("valid_secret", "valid_password", salt=invalid_input)
    with pytest.raises(ValueError):
        encrypt_secret_key("valid_secret", "valid_password", iterations=-1)

# Test Invalid `iterations`, `key_length`, `salt_length`, `nonce_length` Values
@given(st.one_of(st.text(), st.lists(st.integers()), st.floats()))
def test_encrypt_secret_key_invalid_iteration_and_lengths_types(invalid_input):
    with pytest.raises(TypeError):
        encrypt_secret_key("valid_secret", "valid_password", iterations=invalid_input)
    with pytest.raises(ValueError):
        encrypt_secret_key("valid_secret", "valid_password", iterations=-1)  # Example of invalid value

# Functionality with Unusual but Valid Inputs
def test_encrypt_secret_key_with_empty_strings():
    # Assuming the function should accept empty strings and not throw an error
    result = encrypt_secret_key("", "")
    assert isinstance(result, dict) and result["encrypted_key"] != b""

# Test Consistency of Encryption
def test_encrypt_secret_key_consistency():
    secret_key = 'consistent_secret'
    password = 'consistent_password'
    salt = os.urandom(defaults.SALT_LENGTH)
    nonce = os.urandom(defaults.NONCE_LENGTH)
    first_result = encrypt_secret_key(secret_key, password, salt=salt, nonce=nonce)
    second_result = encrypt_secret_key(secret_key, password, salt=salt, nonce=nonce)
    assert first_result['encrypted_key'] == second_result['encrypted_key'], "Encryption should be consistent with same parameters"

# Test Uniqueness of Outputs
def test_encrypt_secret_key_unique_outputs():
    secret_key = 'unique_secret'
    password = 'unique_password'

    len_first_salt = 16
    len_second_salt = 32
    first_result = encrypt_secret_key(secret_key, password, salt_length=len_first_salt)
    second_result = encrypt_secret_key(secret_key, password, salt_length=len_second_salt)
    assert first_result['encrypted_key'] != second_result['encrypted_key'], "Different salts should produce different encrypted keys"

    ## Again for nonce
    len_first_nonce = 12
    len_second_nonce = 24
    first_result = encrypt_secret_key(secret_key, password, nonce_length=len_first_nonce)
    second_result = encrypt_secret_key(secret_key, password, nonce_length=len_second_nonce)
    assert first_result['encrypted_key'] != second_result['encrypted_key'], "Different nonces should produce different encrypted keys"

    ## Again when using defaults
    first_result = encrypt_secret_key(secret_key, password)
    second_result = encrypt_secret_key(secret_key, password)
    assert first_result['encrypted_key'] != second_result['encrypted_key'], "Same password should produce different encrypted keys"

# Test Encrypted Key Length
def test_encrypt_secret_key_encrypted_key_length():
    secret_key = 'length_test_secret'
    password = 'length_test_password'
    result = encrypt_secret_key(secret_key, password)
    # Assuming AES-GCM encryption, the encrypted key size should be roughly the size of the input plus the GCM tag size (typically 16 bytes).
    expected_length = len(secret_key.encode()) + 16  # This is a simplified check; actual length will depend on encryption details.
    assert len(result['encrypted_key']) >= expected_length, "Encrypted key length should be appropriate for the encryption algorithm"


#####################################
### unit test: decrypt_secret_key ###
#####################################


# Input Type Validation
def test_decrypt_secret_key_input_types():
    with pytest.raises(TypeError):
        decrypt_secret_key(password=123, encrypted_key="test", salt="salt", nonce="nonce", iterations=1000)
    # Add more pytest.raises checks for each argument

# Successful Decryption
def test_decrypt_secret_key_success():
    secret_key = "supersecret"
    password = "correcthorsebatterystaple"
    encryption_result = encrypt_secret_key(secret_key, password)
    decrypted_key = decrypt_secret_key(
        password=password,
        **encryption_result
    )
    assert decrypted_key == secret_key, "Decrypted key should match the original"

# Decryption with Incorrect Password
def test_decrypt_secret_key_wrong_password():
    secret_key = "supersecret"
    password = "correcthorsebatterystaple"
    encryption_result = encrypt_secret_key(secret_key, password)
    with pytest.raises(DecryptException):
        decrypt_secret_key(
            password="wrongpassword",
            **encryption_result
        )

# Decryption with Tampered Data
def test_decrypt_secret_key_tampered_data():
    secret_key = "supersecret"
    password = "correcthorsebatterystaple"
    encryption_result = encrypt_secret_key(secret_key, password)
    tampered_encrypted_key = encryption_result['encrypted_key'][:-1] + (encryption_result['encrypted_key'][-1] ^ 0xFF).to_bytes(1, byteorder='big')
    with pytest.raises(DecryptException):
        decrypt_secret_key(
            password=password,
            encrypted_key=tampered_encrypted_key,
            salt=encryption_result['salt'],
            nonce=encryption_result['nonce'],
            iterations=encryption_result['iterations'],
            key_length=encryption_result['key_length']
        )

# Edge Case: Zero-Length Encrypted Key
def test_decrypt_zero_length_encrypted_key():
    password = "testpassword"
    with pytest.raises(DecryptException):
        decrypt_secret_key(
            password=password,
            encrypted_key=b'',
            salt=os.urandom(defaults.SALT_LENGTH),
            nonce=os.urandom(defaults.NONCE_LENGTH),
            iterations=defaults.ITERATIONS,
            key_length=defaults.KEY_LENGTH
        )

# Edge Case: Extreme Lengths for Salt and Nonce
@pytest.mark.parametrize("salt_length, nonce_length", [(1, 1), (128, 128)])
def test_decrypt_extreme_lengths_salt_nonce(salt_length, nonce_length):
    password = "testpassword"
    secret_key = "secret"
    # Use the encrypt function to get valid encrypted_key, then adjust salt and nonce lengths
    encryption_result = encrypt_secret_key(secret_key, password)
    with pytest.raises(DecryptException):
        decrypt_secret_key(
            password=password,
            encrypted_key=encryption_result['encrypted_key'],
            salt=os.urandom(salt_length),
            nonce=os.urandom(nonce_length),
            iterations=defaults.ITERATIONS,
            key_length=defaults.KEY_LENGTH
        )

# Boundary Iterations and Key Length (16, 24, 32)
@pytest.mark.parametrize("iterations, key_length", itertools.product([1, defaults.ITERATIONS, 1000], [16, 24, 32]))
def test_decrypt_boundary_iterations_key_length(iterations, key_length):
    password = "testpassword"
    secret_key = "secret"
    encryption_result = encrypt_secret_key(secret_key, password, iterations=iterations, key_length=key_length)
    decrypted_key = decrypt_secret_key(
        password=password,
        **encryption_result
    )
    assert decrypted_key == secret_key, "Decryption should succeed with boundary values for iterations and key length"