import warnings
import requests
from config import url_nad, login, password
def check():
    #функция вывода содержимого реп. списка
    warnings.filterwarnings('ignore')  
    r = requests.Session()
    response = r.post(url_nad + "/auth/login", json={"username": login, "password": password}, verify=False)
    name = input('Введите название репутационного списка: ')
    response = r.get(url_nad + f'/replists?search={name}')
    checker_id = response.json()
    id = checker_id['results'][0].get('id')
    response = r.get(url_nad + f'/replists/{id}')
    checker = response.json()
    if ("items_count" in checker ):
        size = checker['items_count']
    if ("content" in checker and len(checker['content']) > 0):
        print(f'Список {name} найден.')
        content = checker['content']
        print(f'Количество элементов: {size}')
        print('Содержимое списка:')
        print(content)


    else:
        print(f'Список {name} не был найден!')
        return
