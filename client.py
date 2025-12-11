# client.py — Упрощённый TLS 1.3 клиент (ECDHE + HKDF + AES-GCM)
import socket
import os
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Цвета для консоли (опционально)
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

log("Клиент: Запуск...")

client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_sock.connect(('localhost', 12345))
log("Клиент: Подключён к серверу localhost:12345")

# 1. Генерируем клиентские ephemeral ECDHE ключи
log("Клиент: Генерация ephemeral ECDHE ключей...")
client_private = ec.generate_private_key(ec.SECP256R1())
client_public = client_private.public_key()
client_pub_bytes = client_public.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
log(f"Клиент: Клиентский публичный ключ готов (длина: {len(client_pub_bytes)} байт)")

# 2. Отправляем клиентский публичный ключ серверу
client_sock.sendall(client_pub_bytes)
log("Клиент: Отправлен клиентский публичный ключ серверу")

# 3. Получаем серверный публичный ключ
server_pub_bytes = client_sock.recv(1024)
if len(server_pub_bytes) != 65:
    log("Клиент: Ошибка — неверная длина серверного ключа!", success=False)
    client_sock.close()
    exit(1)
log(f"Клиент: Получен серверный публичный ключ (длина: {len(server_pub_bytes)} байт)")
server_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub_bytes)

# 4. Вычисляем shared secret
log("Клиент: Вычисление shared secret...")
shared_secret = client_private.exchange(ec.ECDH(), server_public)
log(f"Клиент: Shared secret вычислен (длина: {len(shared_secret)} байт; ожидалось 32)", success=len(shared_secret) == 32)

# 5. Derivation handshake secret через HKDF
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'',
    info=b'tls13 handshake key expansion',
)
hs_key = hkdf.derive(shared_secret)
log("Клиент: Handshake secret derived (готов к шифрованию)")

# 6. Отправляем зашифрованное сообщение серверу
message = "Привет от клиента! Это строго секретное сообщение в TLS 1.3.".encode('utf-8')
nonce = os.urandom(12)  # Случайный nonce
aesgcm = AESGCM(hs_key)
ciphertext = aesgcm.encrypt(nonce, message, None)
client_sock.sendall(nonce + ciphertext)
log(f"Клиент: Отправлено зашифрованное сообщение (длина: {len(ciphertext)} байт)")

# 7. Получаем зашифрованный ответ от сервера
nonce_back = client_sock.recv(12)
if len(nonce_back) != 12:
    log("Клиент: Ошибка — неверная длина nonce!", success=False)
    client_sock.close()
    exit(1)
ciphertext_back = client_sock.recv(1024)
log(f"Клиент: Получен зашифрованный ответ (длина: {len(ciphertext_back)} байт)")

# Расшифровка
try:
    decrypted_back = aesgcm.decrypt(nonce_back, ciphertext_back, None)
    log(f"Клиент: Расшифровано: {decrypted_back.decode('utf-8')}")
    log("Клиент: Расшифровка успешна", success=True)
except Exception as e:
    log(f"Клиент: Ошибка расшифровки: {str(e)}", success=False)
    client_sock.close()
    exit(1)

client_sock.close()
log("Клиент: Завершён")