import subprocess
import threading
import time
import requests
import sys

def git_clone(branche):
    git_clone = ['git', 'clone', 'https://github.com/ivankirsanov9062/FlowForge.git', '-b', branche, 'FlowForge']
    print(f'Клонирование репозитория. Ветка: {branche}')
    result = subprocess.run(git_clone, cwd='/app')
    if result.returncode != 0:
        print("Ошибка при клонировании репозитория")
        sys.exit(1)
            
def build():
        print("Запуск скрипта build.sh")
        result = subprocess.run(['bash', './build.sh'], cwd='/app/FlowForge/')
        if result.returncode != 0:
            print("Ошибка выполнения build.sh")
            sys.exit(1)

class Client:
    def __init__(self, client_name, cwd_path='/app/FlowForge/build/bin'):
        self.client_name = client_name
        self.cwd_path = cwd_path
        self.process = None
        self.stop_event = threading.Event()

    def get_external_ip(self):
        urls = [
            'https://api.ipify.org?format=text',
            'https://ifconfig.me',
            'https://checkip.amazonaws.com/'
        ]
        for url in urls:
            try:
                response = requests.get(url, timeout=5)
                response.raise_for_status()
                return response.text.strip()
            except requests.RequestException as e:
                print(f"Ошибка получения IP от {url}: {e}")
                sys.exit(1)

    def monitor_ip(self, initial_ip):
        while not self.stop_event.is_set():
            time.sleep(30)
            current_ip = self.get_external_ip()
            if current_ip != initial_ip:
                print(f"IP изменился: -> {current_ip}")
                if self.process:
                    self.process.terminate()
                    self.process.wait()
                sys.exit(0)

    def start_client(self):
        print("Запуск клиента")
        self.process = subprocess.Popen(['sudo', f'./{self.client_name}'], cwd=self.cwd_path)

    def check(self, initial_ip):
        self.start_client()
        monitor_thread = threading.Thread(target=self.monitor_ip, args=(initial_ip,))
        monitor_thread.start()

        try:
            self.process.wait()
            self.stop_event.set()
            monitor_thread.join()
            current_ip = self.get_external_ip()
            if current_ip == initial_ip:
                print("IP не изменился, программа завершена с кодом 1")
                sys.exit(1)
            else:
                print("IP изменился, программа завершена с кодом 0")
                sys.exit(0)
        except KeyboardInterrupt:
            print("Прервано пользователем")
            self.process.terminate()
            self.stop_event.set()
            monitor_thread.join()
            sys.exit(1)

def start_server(server_file):
    print("Запуск сервера")
    subprocess.Popen(['sudo', f'./{server_file}'], cwd="/app/FlowForge/build/bin")

def main():
    if len(sys.argv) < 3:
        sys.exit(1)

    branch = sys.argv[1]
    mode = sys.argv[2]
    start_file = sys.argv[3:]

    git_clone(branch)
    build()

    if mode == 'client':
        client_arg = start_file[0] if start_file else None
        client = Client(client_arg)
        initial_ip = client.get_external_ip()
        print(f"Начальный внешний IP: {initial_ip}")
        client.check(initial_ip)

    elif mode == 'server':
        server_arg = start_file[0] if start_file else None
        start_server(server_arg)

    else:
        print('Некорректный режим. Пожалуйста, укажите "client" или "server".')

if __name__ == "__main__":
    main()