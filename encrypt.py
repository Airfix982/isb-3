import logging
import os
from serealisation_to_json import serialization_to_json, bytes_from_json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def encryption ( settings: dict, pbar )->None:
    """
    Шифрует текст симметричным шифрованием и сохраняет по указанному пути
    Args:
        settings (dict): набор путей к файлам
        pbar: параметр для показа прогресса
    Return:
    
     """
    pbar.set_description('decrypting symmetric key')
    sym_key_bytes = bytes_from_json(settings['symmetric_key'])
    try:
        with open(settings['secret_key'], 'rb') as pem_in:
                private_bytes = pem_in.read()
    except FileNotFoundError:
         logging.error(f"{settings['secret_key']} not found")

    private_key = load_pem_private_key(private_bytes,password=None,)
    symmetric_key = private_key.decrypt(sym_key_bytes,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                   algorithm=hashes.SHA256(),label=None))
    pbar.update(1)
    pbar.set_description('encrypting and saving the text')
    algorithm = algorithms.Blowfish(symmetric_key)
    backend = default_backend()
    iv = os.urandom(8)
    serialization_to_json(settings['iv'], iv)
    cipher = Cipher(algorithm, mode=modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    data = ''
    try:
         with open(settings['initial_file'], encoding='utf8') as f:
              data = str.encode(f.read())
    except FileNotFoundError:
         logging.error(f"{settings['initial_file']} not found")

    encrypted_text = encryptor.update(bytes(data))
    serialization_to_json(settings['encrypted_file'], encrypted_text)
    pbar.update(1)