import os
import json
import time
import requests
import re
import git  # Добавлен импорт

# Функция для загрузки локальной базы уязвимостей из файла JSON
def load_vulnerability_database(vulnerability_database):
    if os.path.isfile(vulnerability_database):  # Проверяем существование файла
        with open(vulnerability_database, 'r') as f:
            return json.load(f)  # Загружаем и возвращаем содержимое файла JSON
    else:
        print("Ошибка: Некорректный путь к файлу с базой уязвимостей")
        return []

# Функция для сканирования приложения на наличие уязвимостей
def analyze_source_code(source_folder, vulnerabilities):
    findings = []  # Список для хранения найденных уязвимостей

    # Проверяем наличие уязвимости в базе уязвимостей
    for root, dirs, files in os.walk(source_folder):  # Проходим по всем файлам и папкам в исходной папке
        for file in files:  # Проходим по каждому файлу
            if file.endswith(".php"):  # Проверяем, что файл - PHP скрипт
                file_path = os.path.join(root, file)  # Получаем путь к файлу
                with open(file_path, 'r') as f:
                    php_code = f.read()  # Читаем содержимое PHP файла

                    # Проверяем каждую уязвимость из локальной базы уязвимостей
                    for vuln in vulnerabilities:
                        if vuln in php_code:  # Если уязвимость найдена в коде
                            findings.append({  # Добавляем ее в список найденных уязвимостей
                                "title": vuln,
                                "file_path": file_path,
                                #"severity": "High",  # Устанавливаем уровень серьезности уязвимости
                                "description": f"Уязвимость {vuln} обнаружена в файле: {file_path}",
                                "date": time.strftime("%Y-%m-%d %H:%M:%S")  # Устанавливаем дату обнаружения
                            })

    # Если локальные уязвимости не найдены, проводим сканирование на типовые уязвимости
    if not findings:
        findings += scan_for_common_vulnerabilities(source_folder)

    return findings

# Функция для сканирования на типовые уязвимости
def scan_for_common_vulnerabilities(source_folder):
    vulnerabilities = []  # Список для хранения найденных типовых уязвимостей

    # Регулярные выражения для поиска типовых уязвимостей
    sql_pattern = re.compile(r'\b(select|insert|update|delete|drop|truncate|create|alter)\b', re.IGNORECASE)
    xss_pattern = re.compile(r'<script>', re.IGNORECASE)
    csrf_pattern = re.compile(r'<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>', re.IGNORECASE)

    for root, dirs, files in os.walk(source_folder):  # Проходим по всем файлам и папкам в исходной папке
        for file in files:  # Проходим по каждому файлу
            if file.endswith(".php"):  # Проверяем, что файл - PHP скрипт
                file_path = os.path.join(root, file)  # Получаем путь к файлу
                with open(file_path, 'r') as f:
                    php_code = f.read()  # Читаем содержимое PHP файла

                    # Проверяем наличие типовых уязвимостей
                    if sql_pattern.search(php_code):  # Поиск SQL Injection
                        vulnerabilities.append({
                            "title": "SQL Injection",
                            "file_path": file_path,
                            #"severity": "High",
                            "description": f"SQL Injection vulnerability found in file: {file_path}",
                            "date": time.strftime("%Y-%m-%d %H:%M:%S")
                        })

                    if xss_pattern.search(php_code):  # Поиск XSS
                        vulnerabilities.append({
                            "title": "XSS",
                            "file_path": file_path,
                            #"severity": "Medium",
                            "description": f"XSS vulnerability found in file: {file_path}",
                            "date": time.strftime("%Y-%m-%d %H:%M:%S")
                        })

                    if csrf_pattern.search(php_code):  # Поиск CSRF
                        vulnerabilities.append({
                            "title": "CSRF",
                            "file_path": file_path,
                            #"severity": "Low",
                            "description": f"CSRF vulnerability found in file: {file_path}",
                            "date": time.strftime("%Y-%m-%d %H:%M:%S")
                        })

    return vulnerabilities

# Функция для записи найденных уязвимостей в файл JSON
def write_findings_to_file(findings, output_file):
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=4)  # Записываем список уязвимостей в файл JSON с отступами

# Функция для загрузки отчета о найденных уязвимостях в DefectDojo
def upload_report_to_defectdojo(report_data, url, api_key, product_name, engagement_name):
    headers = {
        'Authorization': f'Token {api_key}',
        'Content-Type': 'application/json'  # Устанавливаем тип контента для передачи JSON данных
    }

    try:
        response = requests.post(url, headers=headers, json=report_data)  # Отправляем POST-запрос с данными отчета
        if response.status_code == 201:  # Если отчет успешно загружен
            print("Отчет успешно загружен в DefectDojo.")
        else:  # Если возникла ошибка при загрузке отчета
            print(f"Ошибка при загрузке отчета в DefectDojo: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Ошибка при отправке запроса: {e}")

# Функция для преобразования полученного файла с уязвимостями в формат JSON для загрузки в DefectDojo
def convert_to_defectdojo(input_json):
    defectdojo_json = {
        "product": {
            "name": "UnSAFE_Bank",  # Название продукта
            "description": "Описание продукта"  # Описание продукта
        },
        "engagement": {
            "name": "Security Testing",  # Название проекта
            "description": "Описание проекта",  # Описание проекта
            "target_start": "YYYY-MM-DD",  # Дата начала проекта
            "target_end": "YYYY-MM-DD"  # Дата окончания проекта
        },
        "test": {
            "test_type": "Тип тестирования",  # Тип тестирования
            "environment": "Окружение тестирования"  # Окружение тестирования
        },
        "findings": []
    }

    # Пример: преобразуем каждый элемент исходного JSON в объект finding для DefectDojo
    for item in input_json:
        finding = {
            "title": item["title"],
            "file_path": item["file_path"],
            "severity": "Low",  # Уровень серьезности уязвимости
            "description": "Описание уязвимости"  # Описание уязвимости
        }
        defectdojo_json["findings"].append(finding)

    return defectdojo_json

# Основная функция для сканирования, создания отчета и записи в файл
def main():
    # Замените YOUR_GITLAB_URL, YOUR_PROJECT_ID и YOUR_FILE_PATH на соответствующие значения
    gitlab_url = 'YOUR_GITLAB_URL/api/v4/projects/YOUR_PROJECT_ID/repository/files/YOUR_FILE_PATH/raw'

    # Замените YOUR_PRIVATE_TOKEN на ваш токен доступа
    headers = {'PRIVATE-TOKEN': 'YOUR_PRIVATE_TOKEN'}

    response = requests.get(gitlab_url, headers=headers)

    if response.status_code == 200:
        file_content = response.text
        # Теперь вы можете сканировать содержимое файла на наличие уязвимостей
    else:
        print("Ошибка при получении файла:", response.status_code)

    source_folder = 'repo/Backend'  # Путь к папке с исходным кодом приложения (клонированному репозиторию)
    vulnerability_database = 'nvdcve-1.1-modified.json'  # Путь к файлу с локальной базой уязвимостей
    output_file = 'findings.json'  # Путь к файлу для записи найденных уязвимостей
    url = 'http://192.168.56.102:8080/api/v2/import-scan/'  # URL для загрузки отчета в DefectDojo
    api_key = 'b0ef16376173887e9fc973fceab0d49e611d6c6e'  # Ключ API для доступа к DefectDojo API
    product_name = "UnSAFE_Bank"  # Имя продукта в DefectDojo
    engagement_name = "Security Testing"  # Имя вовлечения в DefectDojo

    # Загрузка локальной базы уязвимостей
    vulnerabilities = load_vulnerability_database(vulnerability_database)

    # Сканирование приложения на наличие уязвимостей
    findings = analyze_source_code(source_folder, vulnerabilities)

    # Запись найденных уязвимостей в файл
    if findings:
        write_findings_to_file(findings, output_file)
        print(f"Найденные уязвимости записаны в файл: {output_file}")

        # Преобразование найденных уязвимостей в формат JSON для загрузки в DefectDojo
        defectdojo_data = convert_to_defectdojo(findings)

        # Загрузка отчета в DefectDojo
        upload_report_to_defectdojo(defectdojo_data, url, api_key, product_name, engagement_name)
    else:
        print("Не найдено уязвимостей.")

if __name__ == "__main__":
    main()
