# server.py — Упрощённый TLS 1.3 сервер (ECDHE + HKDF + AES-GCM)
import socket
import os
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Цвета для консоли (опционально, работает в большинстве терминалов)
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def log(message, success=None):
    timestamp = time.strftime("%H:%M:%S")
    if success is True:
        print(f"[{timestamp}] {GREEN}{message}{RESET}")
    elif success is False:
        print(f"[{timestamp}] {RED}{message}{RESET}")
    else:
        print(f"[{timestamp}] {message}")

log("Сервер: Запуск...")

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(('localhost', 12345))
server_sock.listen(1)
log("Сервер: Слушает на localhost:12345")

conn, addr = server_sock.accept()
log(f"Сервер: Подключён клиент {addr}")

# 1. Получаем клиентский публичный ключ (key_share)
client_pub_bytes = conn.recv(1024)
if len(client_pub_bytes) != 65:  # Ожидаемая длина для secp256r1 uncompressed
    log("Сервер: Ошибка — неверная длина клиентского ключа!", success=False)
    conn.close()
    exit(1)
log(f"Сервер: Получен клиентский публичный ключ (длина: {len(client_pub_bytes)} байт)")
client_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)

# 2. Генерируем серверные ephemeral ECDHE ключи
log("Сервер: Генерация ephemeral ECDHE ключей...")
server_private = ec.generate_private_key(ec.SECP256R1())
server_public = server_private.public_key()
server_pub_bytes = server_public.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
log(f"Сервер: Серверный публичный ключ готов (длина: {len(server_pub_bytes)} байт)")

# 3. Отправляем серверный публичный ключ клиенту
conn.sendall(server_pub_bytes)
log("Сервер: Отправлен серверный публичный ключ клиенту")

# 4. Вычисляем shared secret
log("Сервер: Вычисление shared secret...")
shared_secret = server_private.exchange(ec.ECDH(), client_public)
log(f"Сервер: Shared secret вычислен (длина: {len(shared_secret)} байт; ожидалось 32)", success=len(shared_secret) == 32)

# 5. Derivation handshake secret через HKDF
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'',
    info=b'tls13 handshake key expansion',
)
hs_key = hkdf.derive(shared_secret)
log("Сервер: Handshake secret derived (готов к шифрованию)")

# 6. Получаем зашифрованное сообщение от клиента
nonce = conn.recv(12)
if len(nonce) != 12:
    log("Сервер: Ошибка — неверная длина nonce!", success=False)
    conn.close()
    exit(1)
ciphertext = conn.recv(1024)
log(f"Сервер: Получено зашифрованное сообщение (длина: {len(ciphertext)} байт)")

# Расшифровка
aesgcm = AESGCM(hs_key)
try:
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    log(f"Сервер: Расшифровано: {decrypted.decode('utf-8')}")
    log("Сервер: Расшифровка успешна", success=True)
except Exception as e:
    log(f"Сервер: Ошибка расшифровки: {str(e)}", success=False)
    conn.close()
    exit(1)

# 7. Отправляем зашифрованный ответ клиенту
message_back = "Привет от сервера! TLS 1.3 работает успешно.".encode('utf-8')
nonce_back = os.urandom(12)  # Случайный nonce
ciphertext_back = aesgcm.encrypt(nonce_back, message_back, None)
conn.sendall(nonce_back + ciphertext_back)
log(f"Сервер: Отправлен зашифрованный ответ (длина: {len(ciphertext_back)} байт)")

conn.close()
server_sock.close()
log("Сервер: Завершён")