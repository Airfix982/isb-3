import json
import logging

def serialization_to_json(file_name: str, text)->None:
     """
    Сереализует str в json файл
    Args:
        file_name (str): имя файла, куда сериализуется текст
        text: объект не пользовательского класса для сереализации
    Return:
     
     """
     try:
        with open(file_name, 'w') as f:
                json.dump(list(text), f)
     except FileNotFoundError:
          logging.error(f"{file_name} not found")

def bytes_from_json(file_name: str)->bytes:
    """
    Десереализует json в bytes и возвращает строку байтов
    Args:
        file_name (str): имя файла, откуда десериализуется текст
    Return:
        data (bytes): строка байтов
     """
    try:
        with open(file_name) as f:
            data = bytes(json.load(f))
            return data
    except FileNotFoundError:
          logging.error(f"{file_name} not found")