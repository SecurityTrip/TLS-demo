# server.py — Реальный TLS 1.3 сервер с красивыми подробными логами
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

log("ЗАПУСК TLS 1.3 СЕРВЕРА", GREEN)
log("─────────────────────────────────────────────────────", CYAN)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

log("SSL контекст создан", YELLOW)
log("Протокол: ТОЛЬКО TLS 1.3 (принудительно)", YELLOW)
log("Сертификат: server.crt (self-signed)", YELLOW)
log("Приватный ключ: server.key", YELLOW)
log("Ожидание подключения на localhost:8443...", CYAN)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('localhost', 8443))
sock.listen(1)

conn, addr = sock.accept()
log(f"Новое TCP-соединение от {addr}", GREEN)

log("Начинаем TLS handshake...", YELLOW)
ssl_conn = context.wrap_socket(conn, server_side=True)

log("HANDSHAKE УСПЕШЕН!", GREEN)
log(f"Версия протокола: {ssl_conn.version()}", GREEN)
log(f"Cipher suite: {ssl_conn.cipher()}", GREEN)
log(f"Ключеобмен: {ssl_conn.shared_ciphers()}", GREEN)
log(f"Серверный сертификат отправлен клиенту", CYAN)

log("Готов к приёму зашифрованных данных...", YELLOW)

data = ssl_conn.recv(4096)
if data:
    text = data.decode('utf-8', errors='replace')
    log(f"ПОЛУЧЕНО ОТ КЛИЕНТА:\n    \"{text}\"", CYAN)

response = "Привет, клиент! Это ответ от настоящего TLS 1.3 сервера. Всё зашифровано и защищено!"
ssl_conn.sendall(response.encode('utf-8'))
log(f"ОТПРАВЛЕН ОТВЕТ КЛИЕНТУ:\n    \"{response}\"", CYAN)

log("Соединение закрывается...", YELLOW)
ssl_conn.close()
sock.close()
log("СЕРВЕР ЗАВЕРШЁН", GREEN)