import logging
import os
from serealisation_to_json import serialization_to_json, bytes_from_json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

def decryption ( settings: dict, pbar )->None:
    """
    Дешифрует текст и сохраняет по указанному пути
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
    pbar.set_description('decrypting the text and saving it')
    algorithm = algorithms.Blowfish(symmetric_key)
    backend = default_backend()
    iv = bytes_from_json(settings['iv'])
    cipher = Cipher(algorithm, mode=modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    enc_data = bytes_from_json(settings['encrypted_file'])
    decrypted_data = decryptor.update(enc_data)
    decrypted_data = decrypted_data.decode('utf8')
    try:
        with open(settings['decrypted_file'], 'w', encoding='utf8') as f:
                f.write(decrypted_data)
    except FileNotFoundError:
         logging.error(f"{settings['decrypted_file']} not found")
    pbar.update(1)