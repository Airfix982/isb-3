import logging
import os
from os import urandom
from serealisation_to_json import serialization_to_json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def key_length()->int:
    """
    Запрашивает у пользователя длину ключа шифрования для
    алгоритма симметричного шифрования
    Args:
        
    Return:
     len (int): длина ключа симметричного шифрования
    """
    len = 0
    while(int(len) < 5 or int(len) > 56):
            print('\nВведите длину ключа в байтах: от 5 до 56\n')
            len = (int)(input())
            return len
    

def generate_keys( settings: dict )->None:
    """
    Генерирует ключи и сереализует их
    Args:
        settings (dict): пути к файлам
    Return:
    
    """
    k_length = key_length()
    symmetric_key = urandom( k_length )

    keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    try:
        with open( settings['public_key'], 'wb' ) as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    except FileNotFoundError:
          logging.error(f"{settings['public_key']} not found")

    try:
        with open( settings['secret_key'], 'wb' ) as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()))
    except FileNotFoundError:
          logging.error(f"{settings['secret_key']} not found")
    
    sym_enc_key = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),label=None))
    serialization_to_json( settings['symmetric_key'], sym_enc_key )