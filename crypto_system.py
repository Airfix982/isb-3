from generation_keys import generate_keys   
from encrypt import encryption
from decrypt import decryption
import argparse
import logging
import json
import os
from tqdm import tqdm

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('-s','--settings_path',default='files\\settings.json',help='Путь к json файлу с путями, default = files\\settings.json', action='store') 
    parser.add_argument('-l','--key_length',default=5,help='Длина ключа симметричного шифрования, дефолт 5 байт', action='store') 
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-gen','--generation',help='Запускает режим генерации ключей', action='store_true')
    group.add_argument('-enc','--encryption',help='Запускает режим шифрования', action='store_true')
    group.add_argument('-dec','--decryption',help='Запускает режим дешифрования', action='store_true')  

    args = parser.parse_args()
    print(args)
    settings_path = args.settings_path
    k_len = int(args.key_length)
    try:
        with open(settings_path) as jf:
            settings = json.load(jf)
    except FileNotFoundError:
        logging.error(f"{settings_path} not found")

    mode = (args.generation, args.encryption, args.decryption)
    print(mode)
    match mode:
        case (True, False, False):
            with tqdm(total=4) as pbar:
                logging.info('Generation keys\n')
                generate_keys(settings, k_len, pbar)
        case (False, True, False):
            with tqdm(total=2) as pbar:
                logging.info('Encryption the file\n')
                encryption(settings, pbar)
        case (False, False, True):
            with tqdm(total=2) as pbar:
                logging.info('Decryption the file\n')
                decryption(settings, pbar)
        case _:
            logging.error("wrong mode")