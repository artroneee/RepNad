import wget
import warnings
import os
import requests
import urllib3
import json
from add import *
from remove import *
from check_list import *


#сбор данных
print("""RᴇᴘNAD ʙʏ ᴀʀᴛʀᴏɴᴇ""")
url_nad = input('Введите адрес вашего NAD в формате https://your_nad_ip/api/v2 : ')
login = input('Введите логин: ')
password = input('Введите пароль: ')
r = requests.Session()
warnings.filterwarnings('ignore') #игнорирование ошибок



def connect():
    #функция установки соединения
    wget.download('https://feodotracker.abuse.ch/downloads/ipblocklist.json')  # скачиваем таблицу
    print()
    warnings.filterwarnings('ignore')

    response = r.post(url_nad + "/auth/login", json={"username": login,"password": password},verify=False) #создаем сессию
    if (response.status_code == 200):
        print('Авторизация прошла успешно. Сессия создана.')
    else:
        exit('Авторизация не удалась.')
    temp_cock = r.cookies.get('sessionid')
    if temp_cock:
        sessionid = temp_cock
    else:
        exit("SESSIONID не найден")
    csrf_token = r.cookies.get('csrftoken')
    if csrf_token:
        csrf = csrf_token
    else:
        exit("CSRF токен не найден")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning())  

    parse_file('ipblocklist.json',csrf, sessionid)

def parse_file(filename ,csrf, sessionid): 
    #функция парсинга файла по ВПО
    ip_malware_pairs = []
    malwares_temp = []
    with open(filename, 'r') as file:
        data = json.load(file) 
        for item in data:
            ip_address = item.get("ip_address")
            malware = item.get("malware")
            if ip_address or malware: 
                if ip_address == '':
                    continue
                elif malware == '':
                    ip_malware_pairs.append((ip_address, 'null'))
                else:
                    ip_malware_pairs.append((ip_address, malware))
                    malwares_temp.append(malware)
    malwares = list(set(malwares_temp))
    print('Найден следующий список ВПО: ', end='')
    for i in range(0, len(malwares)):
        if (i != len(malwares)-1):
            print(malwares[i], end=', ')
        else:
            print(malwares[i])
    os.remove("ipblocklist.json")  # удаляем в конце таблицу
    sort(ip_malware_pairs, malwares,csrf, sessionid)


def sort(ip_malware_pairs, malwares,csrf, sessionid): 
    #функция сортировки по малварям
    filtered_arrays = {} #вывод будет ключ-значение, где ключ- малварь, значения- ипшники

    for malware in malwares:
        filtered_array = [pair[0] for pair in ip_malware_pairs if pair[1] == malware]
        filtered_arrays[malware] = filtered_array


    check_names_and_create_tables(malwares, filtered_arrays,  ip_malware_pairs,csrf, sessionid)


def check_names_and_create_tables(malwares, filtered_arrays, ip_malware_pairs,csrf, sessionid):
    #функция проверки/создания реп листа ( с external_key!!!)
    warnings.filterwarnings('ignore')

    for name in malwares:
        r.headers = {"X-CSRFToken": csrf, "Referer": url_nad} #обязательное условие для POST запроса #если не будет работать, то в качестве реферера указывайте просто https://your_nad_ip/
        check = r.get(url_nad+'/replists?search=LOC_auto_'+name+'_IP', verify=False) 

        if check.status_code == 403:
            print(check.status_code)
            exit('Доступ запрещен!') 
        elif check.status_code == 401:
            print(check.status_code)
            exit('Нарушение аутентификации. Попробуйте снова') 
        elif check.json()['count'] != 0: 
            print(f'Список для ВПО {name} найден!')
        else:
            print(f'Список для ВПО {name} не найден в базе. Выполняется создание...')


            create = r.post(url_nad+'/replists', json={"color": "7","name": "LOC_auto_"+name+"_IP","type": "ip","external_key":name}, verify=False)

            if(create.status_code == 201):
                print(f'Создание списка LOC_auto_{name}_IP выполнено успешно')
            else:
                print(f'Не удалось создать список LOC_auto_{name}_IP')
                print('Ответ сервера:')
                print(create.status_code)
                print(create.text)


    id_of_names(malwares, filtered_arrays) 
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning())

def id_of_names(malwares, filtered_arrays): 
    #функция присваивания id по имени реп списка
    id_of_name={}
    for name in malwares:
        check = r.get(url_nad+f'/replists?search=LOC_auto_{name}_IP', verify=False)
        response = check.json()

        if 'results' in response and len(response['results']) > 0:
            # Получаем значение параметра 'id' для первого элемента в списке 'results'
            id_value = response['results'][0].get('external_key')
            if id_value:
                id_of_name[name] = id_value
                print(f"Значение параметра 'external_key' для списка {name}: {id_value}")
            else:
                exit(f"Параметр 'external_key' не найден в элементе для списка {name}")
        else:
            exit("Ответ от сервера некорректный.")
            print(check.text)

    filtered_arrays = sorted(filtered_arrays.items())
    id_of_name = sorted(id_of_name.items())
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning())


    send_data(id_of_name, filtered_arrays)


def send_data(id_of_name, filtered_arrays):
    #функция добавления адресов в реп список
    warnings.filterwarnings('ignore')
    name_id_pairs={}
    name_id_pairs = dict(sorted(id_of_name))

    for name, id in name_id_pairs.items():
         temp_ip = []
         ips_to_add = []
         for arr in filtered_arrays:
             if arr[0] == name:
                 for i in arr[1]:
                    ips_to_add.append({"value": i})
                    temp_ip.append(i)


         add = r.post(url_nad+f'/replists/dynamic/{name}/_bulk', json=ips_to_add, verify=False)
         print(f"Добавлены IP {', '.join(temp_ip)} в список с названием LOC_auto_{name}_IP")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning())

if __name__ == '__main__':
    while True:
        print('Выберите действие:\nАвтоматическое создание/добавление в реп. список [1]\nРучное добавление адреса [2]\nРучное удаление адреса [3]\nПоказать содержимое реп. списка [4]\nВыход [0]')
        try:
            choice = int(input())
        except ValueError:
            print("Ошибка: Введено нечисловое значение. Программа завершает работу.")
            exit(1)
        if (choice == 1):
            connect()
        elif (choice == 2):
            add()
        elif (choice == 3):
            remove()
        elif (choice == 4):
            check()
        elif (choice == 0):
            exit(0)
        else:
            continue



