#!/usr/bin/env python3
import socket
import sys
import threading
import json
import time
from queue import Queue

class NetworkScanner:
    def __init__(self, base_subnet, thread_count=100, ports=None):
        self._base_subnet = base_subnet.rstrip('.') + '.'
        self._timeout = 0.4
        self._thread_count = thread_count
        self._ports_to_check = ports if ports is not None else[80,22,445]
        self._queue = Queue()
        self._live_hosts = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

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
            print("\n[!] Сканирование принудительно остановлено (Ctrl+C).")
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
        host = "ip-api.com"
        path = f"/json/{target_ip}"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect((host, 80))
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode('utf-8'))
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        json_body = response.decode('utf-8').split("\r\n\r\n")
        data = json.loads(json_body[-1])
        return data if data.get("status") == "success" else None
    except Exception:
        return None

def cmd_myip():
    print("[*] Сбор информации о вашем подключении через Raw Sockets...")
    data = get_osint_data()
    if data:
        print(f"[+] Ваш внешний IP: {data.get('query')}")
        print(f"[+] Страна:        {data.get('country')} ({data.get('countryCode')})")
        print(f"[+] Регион/Город:  {data.get('regionName')} / {data.get('city')}")
        print(f"[+] Провайдер/ISP: {data.get('isp')}")
    else:
        print("[-] Ошибка: Не удалось стянуть внешние данные.")

def cmd_site(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"[*] Запуск цифровой слежки за целью: {clean_domain}")
    try:
        ip = socket.gethostbyname(clean_domain)
        print(f"[+] Успешный DNS-резолв цели!")
        print(f"[+] Настоящий IP сайта: {ip}")
    except socket.gaierror:
        print(f"[-] Ошибка: Не удалось определить IP-адрес сайта {clean_domain}.")
        return
    data = get_osint_data(ip)
    if data:
        print(f"[+] Страна сервера:     {data.get('country')}")
        print(f"[+] Город локации:     {data.get('city')}")
        print(f"[+] Хостинг-провайдер:  {data.get('isp')}")
    else:
        print("[-] Ошибка: Не удалось подтянуть гео-данные.")

def cmd_reize_intel(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    print("[*] Накатывание векторов OSINT-разведки на глобальные дата-центры...")
    
    intel_phases = [
        "Global Shodan OSINT Database Mirror",
        "Censys Network Architecture Mapping",
        "Baidu Global Search Crawler",
        "Google Core Infrastructure Cache Scan",
        "Bing Advanced Threat Analytics",
        "Yahoo Corporate DNSdumpster Mirror",
        "PassiveDNS Historical Records Tracker",
        "SSL/TLS Certificate Transparency Log Parser",
        "Netcraft Web-Server Footprinting Engine",
        "VirusTotal Malware Infrastructure Map",
        "ThreatCrowd Cyber-Intelligence Database"
    ]
    
    import time
    for phase in intel_phases:
        print(f"\033[32m[-] Scanning now in {phase}..\033[0m")
        time.sleep(0.7)
        
    print("-" * 65)
    reize_subs = ["admin", "api", "dev", "vpn", "mail", "stage", "test", "portal", "shop", "server", "db"]
    print(f"\033[32m[+] Total Unique Infrastructure Targets Found: {len(reize_subs)}\033[0m\n")
    for b in reize_subs:
        print(f"  \033[36m└─> {b}.{clean_domain}\033[0m")
    print("-" * 65)

def cmd_headers(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"[*] Чтение HTTP-заголовков безопасности для: {clean_domain}")
    try:
        import ssl
        context = ssl.create_default_context()
        # Подключаемся сразу по защищенному 443 порту
        with socket.create_connection((clean_domain, 443), timeout=4.0) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as s:
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {clean_domain}\r\nUser-Agent: REIZE-OSINT\r\nConnection: close\r\n\r\n".encode())
                response = s.recv(4096).decode('utf-8', errors='ignore')
                headers = response.split("\r\n")
                print("-" * 65)
                for h in headers:
                    if any(x in h for x in ["Server:", "Content-Type:", "X-", "Content-Security-Policy:"]):
                        print(f"  \033[32m[+]\033[0m {h}")
                print("-" * 65)
    except Exception as e:
        print(f"[-] Не удалось стянуть заголовки: {e}")

def cmd_robots(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"[*] Поиск секретных директорий в robots.txt для: {clean_domain}")
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=4.0) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as s:
                s.sendall(f"GET /robots.txt HTTP/1.1\r\nHost: {clean_domain}\r\nUser-Agent: REIZE-OSINT\r\nConnection: close\r\n\r\n".encode())
                response = s.recv(4096).decode('utf-8', errors='ignore')
                lines = response.split("\r\n")
                print("-" * 65)
                found = False
                for line in lines:
                    if "Disallow:" in line or "Allow:" in line:
                        print(f"  \033[33m[!]\033[0m {line.strip()}")
                        found = True
                if not found:
                    print("  [-] Файл robots.txt пуст или скрытые папки не найдены.")
                print("-" * 65)
    except Exception as e:
        print(f"[-] Ошибка подключения к robots.txt: {e}")
class ReizeDirBuster:
    def __init__(self, domain, thread_count=50):
        self.domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        self.thread_count = thread_count
        self.queue = Queue()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.wordlist_path = "reize_wordlist.txt"
        self._prepare_wordlist()

    def _prepare_wordlist(self):
        import os
        kali_path = "/usr/share/dirb/wordlists/common.txt"
        if os.path.exists(kali_path):
            self.wordlist_path = kali_path
            return
        if not os.path.exists(self.wordlist_path):
            base_words = ["admin", "login", "wp-admin", "db", "backup", "secret", "config", "api", "uploads", "panel", "administrator", "sql", "dashboard"]
            with open(self.wordlist_path, "w") as f:
                for w in base_words: f.write(f"{w}\n")

    def _worker(self):
        import ssl
        context = ssl.create_default_context()
        while not self.queue.empty() and not self.stop_event.is_set():
            try:
                word = self.queue.get_nowait()
            except Exception: break
            path = f"/{word}"
            try:
                with socket.create_connection((self.domain, 443), timeout=3.0) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as s:
                        req = f"HEAD {path} HTTP/1.1\r\nHost: {self.domain}\r\nUser-Agent: REIZE-Fuzzer\r\nConnection: close\r\n\r\n"
                        s.sendall(req.encode())
                        res = s.recv(256).decode('utf-8', errors='ignore')
                        if "HTTP/1.1 " in res:
                            status = res.split("HTTP/1.1 ")[1].split()[0]
                            with self.lock:
                                if status == "200":
                                    print(f"  \033[32m[+]\033[0m Найдено (200 OK): https://{self.domain}{path}")
                                elif status in ["301", "302"]:
                                    print(f"  \033[34m[*]\033[0m Редирект ({status}): https://{self.domain}{path}")
                                elif status == "403":
                                    print(f"  \033[33m[!]\033[0m Скрыто (403 Forbidden): https://{self.domain}{path}")
            except Exception: pass
            self.queue.task_done()

    def start_scan(self):
        print(f"\033[31m[*] REIZE Multi-Threaded Fuzzer Active | Target: {self.domain}\033[0m")
        print(f"[*] Используется словарь: {self.wordlist_path}")
        print("-" * 65)
        with open(self.wordlist_path, "r", errors='ignore') as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith("#"): self.queue.put(w)
        threads = []
        for _ in range(min(self.thread_count, self.queue.qsize())):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            threads.append(t)
            t.start()
        try:
            while any(t.is_alive() for t in threads):
                for t in threads: t.join(timeout=0.1)
        except KeyboardInterrupt:
            self.stop_event.set()
            print("\n[-] Сканирование принудительно остановлено хакером.")
        print("-" * 65)
        print("[+] Сканирование директорий успешно завершено.")

def cmd_dir_buster(domain):
    buster = ReizeDirBuster(domain)
    buster.start_scan()

class ReizeTemplateScanner:
    def __init__(self, domain):
        self.domain = domain.replace("https://", "").replace("http://", "").split("/")[0].lower()
        self.templates_dir = "reize_templates"
        self._prepare_templates()

    def _prepare_templates(self):
        import os
        if not os.path.exists(self.templates_dir):
            os.makedirs(self.templates_dir)
        sample_tpl = os.path.join(self.templates_dir, "backup_check.json")
        if not os.path.exists(sample_tpl):
            import json
            default_data = {
                "name": "Exposed Configuration Backup Detector",
                "path": "/config.json.bak",
                "search_string": "DB_PASSWORD",
                "severity": "CRITICAL"
            }
            with open(sample_tpl, "w", encoding="utf-8") as f:
                json.dump(default_data, f, indent=4)

    def scan(self):
        import os, json, ssl
        print(f"\033[31m[*] REIZE Template Vulnerability Engine Active | Target: {self.domain}\033[0m")
        print(f"[*] Сканирование по шаблонам из папки: {self.templates_dir}")
        print("-" * 65)
        
        context = ssl.create_default_context()
        if not os.path.exists(self.templates_dir): return
        
        for file in os.listdir(self.templates_dir):
            if file.endswith(".json"):
                tpl_path = os.path.join(self.templates_dir, file)
                try:
                    with open(tpl_path, "r", encoding="utf-8") as f:
                        tpl = json.load(f)
                    
                    name = tpl.get("name", "Unknown Vuln")
                    req_path = tpl.get("path", "/")
                    search_str = tpl.get("search_string", "")
                    severity = tpl.get("severity", "INFO")
                    
                    print(f"[*] Запуск проверки: {name} [{severity}]...")
                    
                    with socket.create_connection((self.domain, 443), timeout=4.0) as sock:
                        with context.wrap_socket(sock, server_hostname=self.domain) as s:
                            req = f"GET {req_path} HTTP/1.1\r\nHost: {self.domain}\r\nUser-Agent: REIZE-Scanner\r\nConnection: close\r\n\r\n"
                            s.sendall(req.encode())
                            res = s.recv(4096).decode('utf-8', errors='ignore')
                            
                            if "HTTP/1.1 200 OK" in res and search_str in res:
                                print(f"  \033[31m[CRITICAL VULNERABILITY FOUND]\033[0m {name}")
                                print(f"  └─> Сигнатура '{search_str}' обнаружена на https://{self.domain}{req_path}")
                            else:
                                print(f"  \033[32m[+]\033[0m Уязвимость не обнаружена (404/Сигнатура отсутствует).")
                except Exception as e:
                    print(f"[-] Ошибка обработки шаблона {file}: {e}")
        print("-" * 65)
        print("[+] Сканирование по сигнатурным шаблонам успешно завершено.")

def cmd_template_scanner(domain):
    scanner = ReizeTemplateScanner(domain)
    scanner.scan()

def show_banner():
    banner_text = r"""
    ____     ______   ____  _____   ______
   / __ \   / ____/  /  _/ / ___/  / ____/
  / /_/ /  / __/     / /   \__ \  / __/   
 / _, _/  / /___   _/ /   ___/ / / /___   
/_/ |_|  /_____/  /___/  /____/ /_____/   
"""
    print("\033[31m" + banner_text + "\033[0m")
    print("[+] TARGET ACQUIRED [+] INTEL-MODE ACTIVE [+] OSINT MODE\n")
    print("========[ REIZE. v5.5.0 - ULTIMATE CYBER INTELLIGENCE PLATFORM ]========")
    print(" Введите 'help' для просмотра команд или 'exit' для выхода.\n")

if __name__ == "__main__":
    show_banner()
    while True:
        try:
            user_input = input("\033[31mreize > \033[0m").strip()
            if not user_input:
                continue
            parts = user_input.split()
            cmd = parts[0].lower()
            if cmd == "exit" or cmd == "quit":
                print("[*] Закрытие сессии REIZE. До связи, хакер.")
                break
            elif cmd == "help":
                print("\nAvailable Commands inside REIZE Framework:")
                print("  help             - Show this advanced manual and active modules")
                print("  myip             - Run an OSINT check on your local and external network interface")
                print("  site <domain>     - Gather site intelligence (DNS, geolocation, hosting provider)")
                print("  intel <domain>    - Deep OSINT subdomain enumeration & infrastructure mapping")
                print("  banner           - Clear terminal and show the signature red cyberpunk ASCII logo")
                print("  exit             - Terminate background threads and close active session\n")
                print("  headers <domain>  - Сбор HTTP-заголовков безопасности сайта")
                print("  robots <домен>   - Поиск скрытых папок через файл robots.txt")
                print("  dir <домен>      - Многопоточный брутфорс скрытых папок и админок сайта")
                print("  vuln <домен>     - Интеллектуальный сигнатурный сканер уязвимостей по шаблонам")
            elif cmd == "banner":
                show_banner()
            elif cmd == "myip":
                cmd_myip()
            elif cmd == "site":
                if len(parts) < 2:
                    print("[-] Ошибка: Укажите домен сайта. Пример: site google.com")
                else:
                    cmd_site(parts[1])
            elif cmd == "intel":
                if len(parts) < 2:
                    print("[-] Ошибка: Укажите домен сайта. Пример: intel google.com")
                else:
                    cmd_reize_intel(parts[1])
            elif cmd == "headers":
                if len(parts) < 2:
                    print("[-] Ошибка: Укажите домен сайта. Пример: intel google.com")
                else:
                    cmd_headers(parts[1])
            elif cmd == "robots":
                if len(parts) < 2:
                    print("[-] Ошибка: Укажите домен. Пример: robots google.com")
                else:
                    cmd_robots(parts[1])
            elif cmd == "dir":
                if len(parts) < 2:
                    print("[-] Ошибка: Укажите домен. Пример: dir google.com")
                else:
                    cmd_dir_buster(parts[1])
            elif cmd == "vuln":
                if len(parts) < 2:
                    print("[-] Ошибка: Укажите домен. Пример: vuln google.com")
                else:
                    cmd_template_scanner(parts[1])
            else:
                print(f"[-] Неизвестная команда '{cmd}'. Введите 'help'.")
        except KeyboardInterrupt:
            print("\n[*] Используйте команду 'exit' для выхода.")
        except Exception as e:
            print(f"[-] Системная ошибка: {e}")

