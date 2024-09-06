__author__ = 'https://github.com/password123456/'
__date__ = '2024.09.01'
__version__ = '1.0'
__status__ = 'Production'

import os
import sys
import json
from datetime import datetime, timedelta
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(original_access_key_string, passphrase_key, nonce):
    encryptor = Cipher(
        algorithms.AES(passphrase_key), 
        modes.GCM(nonce),                
        backend=default_backend()
    ).encryptor()

    encrypted_data = encryptor.update(original_access_key_string.encode()) + encryptor.finalize()
    encrypted_access_key = b64encode(nonce + encryptor.tag + encrypted_data).decode('utf-8')
    return encrypted_access_key


def decrypt(keydb, encrypted_access_key):
    original_access_key_string = None
    passphrase_key = get_key_data(keydb, encrypted_access_key)

    try:
        if passphrase_key:
            passphrase_key = b64decode(passphrase_key)
            encrypted_access_key_bytes = b64decode(encrypted_access_key)

            nonce = encrypted_access_key_bytes[:12]
            tag = encrypted_access_key_bytes[12:28]
            ciphertext = encrypted_access_key_bytes[28:]

            decryptor = Cipher(
                algorithms.AES(passphrase_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()

            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            original_access_key_string = decrypted_data.decode('utf-8')
    except Exception as e:
        print(str(e))

    return original_access_key_string


def write_to_db(keydb, app_id, passphrase_key, encrypted_access_key):
    try:
        if os.path.exists(keydb):
            mode = 'a'
        else:
            mode = 'w'
        with open(keydb, mode, encoding='utf-8') as f:
            f.write(f'{datetime.now()}|{app_id}|{b64encode(passphrase_key).decode("utf-8")}|{encrypted_access_key}\n')
    except Exception as e:
        print(str(e))


def get_key_data(keydb, encrypted_access_key):
    with (open(keydb, 'r', encoding='utf-8') as f):
        for line in f:
            if line.startswith('#') or len(line.strip()) == 0:
                continue

            if str(line.split('|')[3].strip()) == str(encrypted_access_key):
                passphrase_key = line.split('|')[2].strip()
                break
    return passphrase_key


def validate_access_key(access_key, remote_addr):
    current_timestamp = int(datetime.now().timestamp())  
    try:
        access_key = json.loads(access_key)

        if 'exp' not in access_key:
            raise KeyError('exp key is missing')

        if current_timestamp > int(access_key["exp"]):
            print(' - Key is expired')
            return False
        else:
            print(' - Key is valid')

        if 'allow_ips' not in access_key:
            raise KeyError('allow_ips key is missing')

        allowed_ips = access_key['allow_ips']
        print(f'Access Key Allowed: {allowed_ips}')

        if remote_addr in allowed_ips:
            print(f' - Remote address {remote_addr} is allowed')
            return True
        else:
            print(f' - Remote address {remote_addr} is not allowed')
            return False
    except KeyError as e:
        print(f'Error: {str(e)}. Key is invalid or expired.')
        return False
    except ValueError as e:
        print(f'Invalid data format: {str(e)}')
        return False


def main():
    home_path = os.path.dirname(os.path.realpath(__file__))
    keydb = os.path.join(home_path, 'key.db')

    passphrase_key_size = 32
    passphrase_key = os.urandom(passphrase_key_size)

    nonce_size = 12
    nonce = os.urandom(nonce_size)

    issuer = 'key-generator'
    app_id = 'myapps'

    iat_time = datetime.utcnow()
    exp_time = iat_time + timedelta(days=90)

    allow_ips = ['192.168.1.1', '192.168.1.2']

    original_access_key_string_dict = {
        'iss': issuer,
        'app_id': app_id,
        'iat': int(iat_time.timestamp()),
        'exp': int(exp_time.timestamp()),
        'allow_ips': allow_ips
    }

    original_access_key_string = json.dumps(original_access_key_string_dict)
    encrypted_access_key = encrypt(original_access_key_string, passphrase_key, nonce)
    print(f'Encrypted Access Key: {encrypted_access_key}')

    if encrypted_access_key:
        write_to_db(keydb, app_id, passphrase_key, encrypted_access_key)

    decrypted_access_key = decrypt(keydb, encrypted_access_key)
    print(f'Decrypted Access Key: {decrypted_access_key}')

    if decrypted_access_key:
        remote_addr = '192.168.10.1'
        validate_access_key(decrypted_access_key, remote_addr)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as error:
        print(str(error))
