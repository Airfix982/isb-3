import logging
import os
from serealisation_to_json import serialization_to_json, bytes_from_json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def encryption ( settings: dict )->None:
    """
    Шифрует текст симметричным шифрованием и сохраняет по указанному пути
    Args:
        settings (dict): набор путей к файлам
    Return:
    
     """
    sym_key_bytes = bytes_from_json(settings['symmetric_key'])
    try:
        with open(settings['secret_key'], 'rb') as pem_in:
                private_bytes = pem_in.read()
    except FileNotFoundError:
         logging.error(f"{settings['secret_key']} not found")

    private_key = load_pem_private_key(private_bytes,password=None,)
    symmetric_key = private_key.decrypt(sym_key_bytes,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                   algorithm=hashes.SHA256(),label=None))
    
    algorithm = algorithms.ARC4(symmetric_key)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    try:
         with open(settings['initial_file'], 'r') as f:
              data = f.read()
    except FileNotFoundError:
         logging.error(f"{settings['initial_file']} not found")

    encrypted_text = encryptor.update(bytes(data))
    serialization_to_json(settings['encrypted_file'], encrypted_text)