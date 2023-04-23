import argparse
import blowfish
import json
import os
from os import urandom
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def key_length()->int:
    # CBC-CTS
    amount = 0
    while(int(amount) < 5 or int(amount) > 56):
        print('\nВведите длину ключа в байтах: от 5 до 56\n')
        amount = (int)(input())
    
    return amount

def serialization_2_json(file_name: str, word)->None:
     with open(file_name, 'w') as f:
        json.dump(list(word), f)

def initial_vec(settings: dict):
    iv = urandom(8)
    serialization_2_json(settings['initialization_vector'], iv)


def encoding_public_key(settings: dict)->None:
    initial_vec(settings)
    iv = ''
    with open(settings['initialization_vector'], 'r') as f:
        iv = bytes(json.load(f))
    sym_key = ''
    with open(settings['symmetric_key'], 'r') as f:
       sym_key = bytes(json.load(f))
    with open(settings['public_key'], 'rb') as pem_in:
        public_bytes = pem_in.read()
    d_public_key = load_pem_public_key(public_bytes)
    c_sym_key = d_public_key.encrypt(sym_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    serialization_2_json(settings['encrypted_symmetric_key'], c_sym_key)


def generating(settings: dict):
    k_length = key_length()
    key = urandom(k_length)
    serialization_2_json(settings['symmetric_key'], key)
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()

    # сериализация открытого ключа в файл
    public_pem = settings['public_key']
    with open(public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # сериализация закрытого ключа в файл
    private_pem = settings['secret_key']
    with open(private_pem, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
            
    encoding_public_key(settings)




def encrypt_the_text(sym_key: bytes, settings: dict):
    cipher = blowfish.Cipher(sym_key)
    with open(settings['initial_file'], encoding='utf8') as f:
        data = str.encode(f.read())#str
    with open(settings['initialization_vector'], 'r') as f:
        iv = bytes(json.load(f))#bytes
    data_encrypted = b"".join(cipher.encrypt_cbc_cts(bytes(data), iv))
    data_decrypted = b"".join(cipher.decrypt_cbc_cts(data_encrypted, iv))
    data_decrypted = data_decrypted.decode('utf8')
    serialization_2_json(settings['encrypted_file'], data_encrypted)
    

def encrypting(settings: dict):
    sym_key_enc = ''
    with open(settings['encrypted_symmetric_key'], 'r') as f:
        sym_key_enc = bytes(json.load(f))

    with open(settings['secret_key'], 'rb') as pem_in:
        secret_bytes = pem_in.read()
    secret_key = load_pem_private_key(secret_bytes,password=None,)

    sym_key = secret_key.decrypt(sym_key_enc,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    encrypt_the_text(sym_key, settings)

def decrypt_the_text(sym_key: bytes, settings: dict):
    cipher = blowfish.Cipher(sym_key)
    with open(settings['encrypted_file']) as f:
        data = bytes(json.load(f))
    with open(settings['initialization_vector'], 'r') as f:
        iv = bytes(json.load(f))
    data_decrypted = b"".join(cipher.decrypt_cbc_cts(data, iv))
    data_decrypted = data_decrypted.decode('utf8')
    with open(settings['decrypted_file'], 'w', encoding='utf8') as f:
        f.write(data_decrypted)


def decrypting(settings):
    sym_key_enc = ''
    with open(settings['encrypted_symmetric_key'], 'r') as f:
        sym_key_enc = bytes(json.load(f))

    with open(settings['secret_key'], 'rb') as pem_in:
        secret_bytes = pem_in.read()
    secret_key = load_pem_private_key(secret_bytes,password=None,)
    sym_key = secret_key.decrypt(sym_key_enc,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    decrypt_the_text(sym_key, settings)
    pass


def main():
    settings= {
    'initial_file':'texts/initial_file.txt',
    'encrypted_file':'texts/encrypted_file.json',
    'decrypted_file':'texts/decrypted_file.txt',
    'symmetric_key':'keys/symmetric_key.json',
    'initialization_vector': 'keys/initialization_vector.json',
    'encrypted_symmetric_key':'keys/encrypted_symmetric_key.json',
    'public_key':'keys/public_key.pem',
    'secret_key':'keys/secret_key.pem',
    }
    if not os.path.isdir('texts'):
        os.mkdir('texts')
    if not os.path.isdir('keys'):
        os.mkdir('keys')
    parser = argparse.ArgumentParser()
    parser.add_argument('-gen','--generation',help='Запускает режим генерации ключей', action="store_true")
    parser.add_argument('-enc','--encryption',help='Запускает режим шифрования', action="store_true")
    parser.add_argument('-dec','--decryption',help='Запускает режим дешифрования', action="store_true")

    args = parser.parse_args()
    
    if args.generation:
        generating(settings)
    else:
        if args.encryption:
            encrypting(settings)
        else: 
            decrypting(settings)

if __name__ == '__main__':
    main()