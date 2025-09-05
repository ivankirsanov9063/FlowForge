import subprocess
import threading
import time
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def build():
        print("Запуск скрипта build.sh", flush=True)
        result = subprocess.run(['bash', './build.sh'], cwd='/app/')
        if result.returncode != 0:
            print("Ошибка выполнения build.sh", flush=True)
            sys.exit(1)

class Client:
    def __init__(self, client_name, cwd_path='/app/build/bin'):
        self.client_name = client_name
        self.cwd_path = cwd_path
        self.process = None
        self.stop_event = threading.Event()
        self.ip_changed_event = threading.Event()
        
    def get_external_ip(self):
        urls = [
            'https://api.ipify.org?format=text',
            'https://ifconfig.me',
            'https://checkip.amazonaws.com/'
        ]
        ip = None
        for url in urls:
            time.sleep(5)
            print(f'Запрос на сайт {url}', flush=True)
            try:
                response = requests.get(url, timeout=3, verify=False)
                response.raise_for_status()
                ip = response.text.strip()
                print(f'Получен IP от {url}: {ip}', flush=True)
            except requests.exceptions.RequestException as e:
                print(f'Ошибка получения IP от {url}: {e}', flush=True)
        if ip:
            return ip
        else:
            print("Не удалось получить внешний IP ни от одного сервиса", flush=True)
            sys.exit(1)

    def monitor_ip(self, initial_ip):
        time.sleep(15)
        while not self.stop_event.is_set():
            try:
                current_ip = self.get_external_ip()
            except SystemExit:
                # Если не удалось получить IP, завершаем мониторинг
                self.stop_event.set()
                return
            # Проверка, что current_ip действительно получен
            if not current_ip:
                print("Не удалось получить текущий IP, завершение программы.", flush=True)
                sys.exit(1)
            if current_ip != initial_ip:
                print(f"IP изменился: {initial_ip} -> {current_ip}", flush=True)
                self.ip_changed_event.set()
                self.stop_event.set()
                return

    def start_client(self):
        print("Запуск клиента", flush=True)
        self.process = subprocess.Popen(
    ['sudo', f'./{self.client_name}'],
    cwd=self.cwd_path,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

    def check(self, initial_ip):
        self.start_client()
        
        # Ждем немного после запуска, чтобы VPN-клиент успел подключиться
        time.sleep(10)  # Настраиваемый таймаут (10 секунд), можно увеличить, если нужно
        
        # Проверяем IP сразу после запуска
        current_ip_after_start = self.get_external_ip()
        if current_ip_after_start == initial_ip:
            print(f"После запуска клиента IP не изменился ({initial_ip}). Завершение программы с кодом 1.", flush=True)
            if self.process:
                self.process.terminate()
                self.process.wait()
            sys.exit(1)
        
        # Если IP изменился, продолжаем мониторинг
        monitor_thread = threading.Thread(target=self.monitor_ip, args=(initial_ip,))
        monitor_thread.start()

        # Ожидаем завершения процесса или изменения IP
        while True:
            # Мониторим, завершился ли процесс
            retcode = self.process.poll()
            if retcode is not None:
                if retcode != 0:
                    print(f"Клиент завершился с ошибкой, код {retcode}", flush=True)
                break
            if retcode is not None:
                # Процесс завершился
                break
            # Проверяем, установлено ли событие смены IP
            if self.ip_changed_event.is_set():
                # IP поменялся — завершаем работу
                self.process.terminate()
                self.process.wait()
                break
            time.sleep(1)

        # После выхода из цикла:
        self.stop_event.set()
        monitor_thread.join()

        # Финальная проверка
        current_ip = self.get_external_ip()
        if self.ip_changed_event.is_set():
            print("IP изменился, программа завершена с кодом 0", flush=True)
            sys.exit(0)
        elif current_ip == initial_ip:
            print("IP не изменился, программа завершена с кодом 1", flush=True)
            sys.exit(1)
        else:
            # Процесс завершился, но IP изменился (редкий случай)
            print("Процесс завершился, IP изменился", flush=True)
            sys.exit(0)


def start_server(server_file):
    print("Запуск сервера", flush=True)
    subprocess.Popen(['sudo', f'./{server_file}'], cwd="/app/build/bin")
    while True:
        pass
    
def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    mode = sys.argv[1]
    start_file = sys.argv[2:]

    build()
    

    if mode == 'client':
        client_arg = start_file[0] if start_file else None
        client = Client(client_arg)
        initial_ip = client.get_external_ip()
        print(f"Начальный внешний IP: {initial_ip}", flush=True)
        client.check(initial_ip)

    elif mode == 'server':
        server_arg = start_file[0] if start_file else None
        start_server(server_arg)

    else:
        print('Некорректный режим. Пожалуйста, укажите "client" или "server".', flush=True)

if __name__ == "__main__":

    main()


