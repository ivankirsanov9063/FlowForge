import subprocess
import threading
import time
import requests
import sys

def get_external_ip():
    urls = ['https://api.ipify.org?format=text', 'https://ifconfig.me', 'https://checkip.amazonaws.com/']
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.text.strip()
        except requests.RequestException as e:
            print(f"Ошибка получения IP от {url}: {e}")
    return None  # Если все попытки не удались

def monitor_ip(initial_ip, process, stop_event):
    """
    Проверяет IP каждые 10 секунд.
    Если IP изменился, останавливает клиент и завершает программу.
    """
    while not stop_event.is_set():
        time.sleep(30)
        current_ip = get_external_ip()
        if current_ip is None:
            continue  # В случае ошибки пропускаем
        if current_ip != initial_ip:
            print(f"IP изменился: -> {current_ip}")
            # Остановим клиентский процесс
            process.terminate()
            process.wait()
            # Завершаем программу с кодом 0
            sys.exit(0)

def main(branche):
    git_clone = ['git', 'clone', 'https://github.com/ivankirsanov9062/FlowForge.git', '-b', branche, 'FlowForge']
    print(f'Клонирование репозитория. Ветка: {branche}')

# Используем subprocess.run, чтобы дождаться завершения клонирования
    result = subprocess.run(git_clone, cwd='/app')
    if result.returncode != 0:
        print("Ошибка при клонировании репозитория")
        sys.exit(1)

    print("Запуск скрипта build.sh")
    build_script = './build.sh'
    result = subprocess.run(['bash', build_script], cwd='/app/FlowForge/')
    if result.returncode != 0:
        print("Ошибка выполнения build.sh")
        sys.exit(1)

    initial_ip = get_external_ip()
    if initial_ip is None:
        print("Не удалось получить внешний IP. Завершение.")
        sys.exit(1)

    print(f"Начальный внешний IP: {initial_ip}")

    print("Запуск клиента")
    client_process = subprocess.Popen(['sudo', './Client'], cwd='/app/FlowForge/build/bin')

    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_ip, args=(initial_ip, client_process, stop_event))
    monitor_thread.start()

    try:
        client_process.wait()
        stop_event.set()
        monitor_thread.join()
        current_ip = get_external_ip()
        if current_ip == initial_ip:
            print("IP не изменился, программа завершена с кодом 1")
            sys.exit(1)
        else:
            print("IP изменился, программа завершена с кодом 0")
            sys.exit(0)
    except KeyboardInterrupt:
        print("Прервано пользователем")
        client_process.terminate()
        stop_event.set()
        monitor_thread.join()
        sys.exit(1)

if __name__ == "__main__":
    main('main')
