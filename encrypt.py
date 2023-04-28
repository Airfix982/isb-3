import logging
import os
from serealisation_to_json import serialization_to_json, bytes_from_json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encryption ( settings: dict )->None:
    sym_key = bytes_from_json(settings['symmetric_key'])
    algorithm = algorithms.ARC4(sym_key)
    cipher = Cipher(algorithm, mode=None)
    #получить секретный ключ и расшифровать симметричный
    encryptor = cipher.encryptor()