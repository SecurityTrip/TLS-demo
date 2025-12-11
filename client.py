# client.py — Реальный TLS 1.3 клиент с красивыми подробными логами
import socket
import ssl
import time
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
context.load_verify_locations("server.crt")  # Доверяем нашему self-signed

log("SSL контекст создан", YELLOW)
log("Протокол: ТОЛЬКО TLS 1.3", YELLOW)
log("Доверенный сертификат: server.crt", YELLOW)
log("Проверка имени хоста: включена", YELLOW)

log("Установка TCP-соединения с localhost:8443...", CYAN)
sock = socket.create_connection(('localhost', 8443))

log("Начинаем TLS handshake...", YELLOW)
ssl_sock = context.wrap_socket(sock, server_hostname="localhost")

log("HANDSHAKE УСПЕШЕН!", GREEN)
log(f"Версия протокола: {ssl_sock.version()}", GREEN)
log(f"Cipher suite: {ssl_sock.cipher()}", GREEN)
log(f"Ключеобмен: {ssl_sock.shared_ciphers()}", GREEN)
log(f"Сертификат сервера получен и проверен", CYAN)

message = "Привет, сервер! Это сообщение передаётся по настоящему TLS 1.3 с ECDHE и AES-GCM!"
ssl_sock.sendall(message.encode('utf-8'))
log(f"ОТПРАВЛЕНО СЕРВЕРУ:\n    \"{message}\"", CYAN)

log("Ожидание ответа от сервера...", YELLOW)
response = ssl_sock.recv(4096)
if response:
    text = response.decode('utf-8')
    log(f"ПОЛУЧЕН ОТВЕТ ОТ СЕРВЕРА:\n    \"{text}\"", CYAN)

ssl_sock.close()
log("КЛИЕНТ ЗАВЕРШЁН", GREEN)