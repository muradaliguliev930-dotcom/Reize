import socket
import threading
from queue import Queue

class NetworkScanner:
    def __init__(self, base_subnet, thread_count=100):
        self._base_subnet = base_subnet
        self._timeout = 0.5
        self._thread_count = thread_count
        self._queue = Queue()
        self._live_hosts = []
        self._lock = threading.Lock()

    def _ping_host(self, ip):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self._timeout)
                result = sock.connect_ex((ip, 80))
                if result == 0:
                    with self._lock:
                        print(f"[!] ЦЕЛЬ ЗАФИКСИРОВАНА: {ip}")
                        self._live_hosts.append(ip)
        except Exception:
            pass

    def _worker(self):
        while not self._queue.empty():
            ip = self._queue.get()
            self._ping_host(ip)
            self._queue.task_done()

    def scan_network(self):
        # Самый безопасный способ задать цвета без ломания синтаксиса
        R = chr(27) + "[91m"
        Y = chr(27) + "[93m"
        C = chr(27) + "[96m"
        RESET = chr(27) + "[0m"

        banner_text = r"""
    ____     ______   ____  _____   ______
   / __ \   / ____/  /  _/ / ___/  / ____/
  / /_/ /  / __/     / /   \__ \  / __/   
 / _, _/  / /___   _/ /   ___/ / / /___   
/_/ |_|  /_____/  /___/  /____/ /_____/   
"""
        # Вывод цветного интерфейса
        print(R + banner_text + RESET)
        print(Y + "[+] TARGET ACQUIRED [+] DIGITAL TRAIL ACTIVE [+] DISCOVERY MODE" + RESET + "\n")
        print("========[ " + C + "REIZE v1.0.0" + RESET + " - CYBERSTALKER NET-DISCOVERY TOOL ]========")
        print(f"[*] Сканирование подсети: {self._base_subnet}1 - 254")
        print("-" * 65)

        for i in range(1, 255):
            self._queue.put(f"{self._base_subnet}{i}")

        threads = []
        for _ in range(min(self._thread_count, 254)):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        print("-" * 65)
        print(f"[*] Разведка завершена. Всего целей на радаре: {len(self._live_hosts)}")

if __name__ == "__main__":
    my_subnet = "172.29.159.22"
    scanner = NetworkScanner(my_subnet, thread_count=100)
    scanner.scan_network()
