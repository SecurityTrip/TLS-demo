# client.py — Реальный TLS 1.3 клиент (красивые логи + переносы)
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

log("ЗАПУСК TLS 1.3 КЛИЕНТА", GREEN)
log("─────────────────────────────────────────────────────", CYAN)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_verify_locations("server.crt")

log("SSL контекст: готов", YELLOW)
log("Протокол: TLS 1.3", YELLOW)
log("Доверенный CA: server.crt", YELLOW)
log("Проверка имени: localhost", YELLOW)

log("Подключение к localhost:8443...", CYAN)
sock = socket.create_connection(('localhost', 8443))

log("Начинаем TLS handshake...", YELLOW)
ssl_sock = context.wrap_socket(sock, server_hostname="localhost")

log("HANDSHAKE УСПЕШЕН!", GREEN)
log(f"Версия: {ssl_sock.version()}", GREEN)

cipher_name, proto, bits = ssl_sock.cipher()
log(f"Cipher suite:", GREEN)
log(f"   {cipher_name} ({bits}-bit)", GREEN)

log("Ключеобмен:", GREEN)
log(f"   ECDHE (perfect forward secrecy)", GREEN)

log("Сертификат сервера проверен", CYAN)
log("Защищённый канал установлен", YELLOW)

message = "Привет, сервер! Это сообщение передаётся по настоящему TLS 1.3!"
ssl_sock.sendall(message.encode('utf-8'))
log("ОТПРАВЛЕНО СЕРВЕРУ:", CYAN)
log(f"   \"{message}\"", CYAN)

log("Ожидание ответа...", YELLOW)
response = ssl_sock.recv(4096)
if response:
    text = response.decode('utf-8')
    log("ПОЛУЧЕН ОТВЕТ:", CYAN)
    log(f"   \"{text}\"", CYAN)

ssl_sock.close()
log("КЛИЕНТ ЗАВЕРШЁН", GREEN)