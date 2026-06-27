import socket
import sys
import threading
import json
from urllib.request import urlopen, Request
from queue import Queue

class NetworkScanner:
    def __init__(self, base_subnet, thread_count=100, ports=[80]):
        self._base_subnet = base_subnet.rstrip('.') + '.'
        self._timeout = 0.4
        self._thread_count = thread_count
        self._ports_to_check = ports
        self._queue = Queue()
        self._live_hosts = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def _ping_host(self, ip):
        if self._stop_event.is_set():
            return
        for port in self._ports_to_check:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self._timeout)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        with self._lock:
                            print(f"\033[92m[!] ЦЕЛЬ ЗАФИКСИРОВАНА: {ip} (Порт {port} ОТКРЫТ)\033[0m")
                            if ip not in self._live_hosts:
                                self._live_hosts.append(ip)
                        return
            except Exception:
                pass

    def _worker(self):
        while not self._queue.empty() and not self._stop_event.is_set():
            try:
                ip = self._queue.get_nowait()
            except Exception:
                break
            self._ping_host(ip)
            self._queue.task_done()

    def scan_network(self):
        print(f"[*] Запуск разведки подсети: {self._base_subnet}1 - 254")
        print(f"[*] Проверяемые порты: {self._ports_to_check}")
        print(f"[*] Потоков задействовано: {self._thread_count}")
        print("-" * 65)

        self._queue = Queue()
        self._live_hosts = []
        self._stop_event.clear()

        for i in range(1, 255):
            self._queue.put(f"{self._base_subnet}{i}")

        threads = []
        for _ in range(min(self._thread_count, 254)):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            threads.append(t)
            t.start()

        try:
            while any(t.is_alive() for t in threads):
                for t in threads:
                    t.join(timeout=0.1)
        except KeyboardInterrupt:
            print("\n\u001b[31m[!] Сканирование принудительно остановлено (Ctrl+C).\033[0m")
            self._stop_event.set()
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except Exception:
                    break

        print("-" * 65)
        print(f"[*] Разведка завершена. Всего целей на радаре: {len(self._live_hosts)}")

def get_osint_data(target_ip=""):
    try:
        url = f"http://ip-api.com{target_ip}"
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            return data if data.get("status") == "success" else None
    except Exception:
        return None

def cmd_myip():
    print("[*] Сбор информации о вашем текущем подключении...")
    data = get_osint_data()
    if data:
        print(f"\033[96m[+] Ваш внешний IP:\033[0m {data.get('query')}")
        print(f"\033[96m[+] Страна:\033[0m        {data.get('country')} ({data.get('countryCode')})")
        print(f"\033[96m[+] Регион/Город:\033[0m  {data.get('regionName')} / {data.get('city')}")
        print(f"\033[96m[+] Провайдер/ISP:\033[0m {data.get('isp')}")
        print(f"\033[96m[+] Организация:\033[0m  {data.get('org')}")
    else:
        print("\033[91m[-] Ошибка: Не удалось связаться с базой OSINT. Проверьте интернет.\033[0m")

def cmd_site(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"[*] Запуск цифровой слежки за целью: {clean_domain}")
    try:
        ip = socket.gethostbyname(clean_domain)
        print(f"\033[92m[+] Успешный DNS-резолв цели!\033[0m")
        print(f"\033[96m[+] Настоящий IP сайта:\033[0m {ip}")
    except socket.gaierror:
        print(f"\033[91m[-] Ошибка: Не удалось определить IP-адрес сайта {clean_domain}.\033[0m")
        return

    data = get_osint_data(ip)
    if data:
        print(f"\033[96m[+] Страна сервера:\033[0m     {data.get('country')}")
        print(f"\033[96m[+] Город локации:\033[0m     {data.get('city')}")
        print(f"\033[96m[+] Хостинг-провайдер:\033[0m  {data.get('isp')}")
        
        isp_name = data.get('isp', '').lower()
        org_name = data.get('org', '').lower()
        print("\033[95m[*] Анализ системы защиты...\033[0m")
        if "cloudflare" in isp_name or "cloudflare" in org_name:
            print("\033[91m[!] ВНИМАНИЕ: Сайт находится под мощной защитой CLOUDFLARE WAF.\033[0m")
        elif "ddos-guard" in isp_name or "ddos-guard" in org_name:
            print("\033[91m[!] ВНИМАНИЕ: Обнаружена защита DDOS-GUARD.\033[0m")
        else:
            print("\033[92m[+] Прямая защита WAF/Cloudflare не обнаружена.\033[0m")
    else:
        print("[-] Предупреждение: Не удалось стянуть гео-данные для IP сервера сайта.")

def show_banner():
    R = "\u001b[31m"
    Y = "\u001b[33m"
    C = "\u001b[36m"
    RESET = "\u001b[0m"
    banner_text = r"""
    ____     ______   ____  _____   ______
   / __ \   / ____/  /  _/ / ___/  / ____/
  / /_/ /  / __/     / /   \__ \  / __/   
 / _, _/  / /___   _/ /   ___/ / / /___   
/_/ |_|  /_____/  /___/  /____/ /_____/   
"""
    print(R + banner_text + RESET)
    print(Y + "[+] TARGET ACQUIRED [+] DIGITAL TRAIL ACTIVE [+] DISCOVERY MODE" + RESET + "\n")
    print("========[ " + C + "REIZE v3.0.0" + RESET + " - INTERACTIVE CYBERSTALKER CONSOLE ]========")
    print(" Введите 'help' для просмотра команд или 'exit' для выхода.\n")

if __name__ == "__main__":
    show_banner()
    
    # Бесконечный цикл интерактивной консоли (как в Metasploit)
    while True:
        try:
            # Твой собственный кастомный хакерский инпут-приглашение!
            user_input = input("\033[91mreize > \033[0m").strip()
            
            if not user_input:
                continue
                
            parts = user_input.split()
            cmd = parts[0].lower()
            
            if cmd == "exit" or cmd == "quit":
                print("[*] Закрытие сессии REIZE. До связи, хакер.")
                break
                
            elif cmd == "help":
                print("\nДоступные команды внутри фреймворка:")
                print("  myip             - Гео-разведка вашего собственного интернет-подключения")
                print("  site <домен>     - OSINT-пробив любого сайта в мире (пример: site google.com)")
                print("  scan <подсеть>   - Быстрый скан подсети по 80 порту (пример: scan 172.29.159.)")
                print("  banner           - Очистить экран и показать логотип заново")
                print("  exit             - Полный выход из программы\n")
                
            elif cmd == "banner":
                print("\033[H\033[J", end="") # Очистка экрана
                show_banner()
                
            elif cmd == "myip":
                cmd_myip()
                
            elif cmd == "site":
                if len(parts) < 2:
                    print("\033[91m[-] Ошибка: Укажите домен сайта. Пример: site google.com\033[0m")
                else:
                    cmd_site(parts[1])
                    
            elif cmd == "scan":
                if len(parts) < 2:
                    print("\033[91m[-] Ошибка: Укажите подсеть. Пример: scan 172.29.159.\033[0m")
                else:
                    target = parts[1]
                    if target.endswith('0'):
                        target = target[:-1]
                    scanner = NetworkScanner(base_subnet=target)
                    scanner.scan_network()
            else:
                print(f"\033[91m[-] Неизвестная команда '{cmd}'. Введите 'help' для списка команд.\033[0m")
                
        except KeyboardInterrupt:
            print("\n[*] Используйте команду 'exit' для выхода из консоли REIZE.")
        except Exception as e:
            print(f"[-] Системная ошибка: {e}")
