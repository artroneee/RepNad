import wget
import warnings
import re
import requests
import urllib3
import json
from config import url_nad, login, password

def validate_ip_address(ip):
    # Регулярное выражение для проверки формата IP адреса
    ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    if re.match(ip_pattern, ip):
        return True
    else:
        return False
def remove():
    #функция удаления адреса(ов) из реп. списка
    warnings.filterwarnings('ignore')
    r = requests.Session()
    response = r.post(url_nad + "/auth/login", json={"username": login,"password": password},verify=False)


    name = input('Введите название репутационного списка: ')
    response = r.get(url_nad +f'/replists?search={name}')
    checker = response.json()
    if ("count" in checker and checker['count'] > 0):
        print(f'Список {name} найден.')
        ext_key = checker['results'][0].get('external_key')
        if ext_key:
            print(f'Список {name} был создан через API. Значение уникального параметра "external_key": {ext_key}')
        else:
            print(f'Список {name} не был создан через API и доступен для изменения в NAD!')
            return
    else:
        print(f'Список {name} не был найден!')
        return
    ips = input(f'Введите IP адрес для удаления из списка {name}. Если адресов несколько, введите их через пробел: ').split(' ')
    for ip in ips:
        if validate_ip_address(ip):
            continue
        else:
            print(f'Ошибка: Введен некорректный IP адрес {ip}.')
            return
    r.headers = {"X-CSRFToken": r.cookies.get_dict()['csrftoken'], "Referer": url_nad} #если не будет работать, то в качестве реферера указывайте просто https://your_nad_ip/
    json = [f"{ip}" for ip in ips]
    response = r.post(url_nad+f'/replists/dynamic/{ext_key}/_delete', json=json)
    if (response.status_code == 204):
        print('Успех')
    else:
        print('Что-то пошло не так:')
        print(response.text)