# server.py — Реальный TLS 1.3 сервер (красивые логи + переносы)
import socket
import ssl
from datetime import datetime

GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"

def log(msg, color=""):
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {color}{msg}{RESET}")

log("ЗАПУСК TLS 1.3 СЕРВЕРА", GREEN)
log("─────────────────────────────────────────────────────", CYAN)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

log("SSL контекст: готов", YELLOW)
log("Протокол: TLS 1.3 (принудительно)", YELLOW)
log("Сертификат: server.crt", YELLOW)
log("Ожидание подключения → localhost:8443", CYAN)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('localhost', 8443))
sock.listen(1)

conn, addr = sock.accept()
log(f"Подключение от {addr}", GREEN)
log("Начинаем TLS handshake...", YELLOW)

ssl_conn = context.wrap_socket(conn, server_side=True)

log("HANDSHAKE УСПЕШЕН!", GREEN)
log(f"Версия: {ssl_conn.version()}", GREEN)

cipher_name, proto, bits = ssl_conn.cipher()
log(f"Cipher suite:", GREEN)
log(f"   {cipher_name} ({bits}-bit)", GREEN)

log("Ключеобмен:", GREEN)
log(f"   ECDHE (forward secrecy включён)", GREEN)  # В TLS 1.3 всегда ECDHE

log("Сертификат отправлен клиенту", CYAN)
log("Защищённый канал установлен", YELLOW)

data = ssl_conn.recv(4096)
if data:
    text = data.decode('utf-8', errors='replace')
    log("ПОЛУЧЕНО ОТ КЛИЕНТА:", CYAN)
    log(f"   \"{text}\"", CYAN)

response = "Привет, клиент! Это настоящий TLS 1.3 с ECDHE и AES-GCM. Всё защищено!"
ssl_conn.sendall(response.encode('utf-8'))
log("ОТПРАВЛЕН ОТВЕТ:", CYAN)
log(f"   \"{response}\"", CYAN)

ssl_conn.close()
sock.close()
log("СЕРВЕР ЗАВЕРШЁН", GREEN)