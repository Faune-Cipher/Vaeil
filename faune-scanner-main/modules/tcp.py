import socket
import threading

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB"
}

class TCPScanner:
    def __init__(self, host, start_port, end_port, timeout=1, threads=100):
        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(threads)

    def _scan_port(self, port):
        self._semaphore.acquire()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.host, port))

            if result == 0:
                banner = None
                try:
                    if port in (80, 8080, 8443):
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        s.send(b"\r\n")
                    data = s.recv(1024)
                    banner = data.decode("utf-8", errors="ignore").strip()[:200]
                except:
                    pass

                service = COMMON_PORTS.get(port, "unknown")
                with self._lock:
                    self.results.append({
                        "port": port,
                        "service": service,
                        "banner": banner if banner else None
                    })
            s.close()
        except socket.error:
            pass
        finally:
            self._semaphore.release()

    def run(self):
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            t = threading.Thread(target=self._scan_port, args=(port,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return sorted(self.results, key=lambda x: x["port"])
