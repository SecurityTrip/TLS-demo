from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

print("Генерация самоподписанного сертификата для localhost...")

# 1. Генерируем приватный ключ RSA-2048
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# 2. Формируем имя (Subject и Issuer одинаковые для self-signed)
name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Moscow"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Moscow"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLS 1.3 Demo"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

# 3. Строим сертификат
cert = x509.CertificateBuilder(
).subject_name(name
               ).issuer_name(name  # self-signed → issuer == subject
                             ).public_key(private_key.public_key()
                                          ).serial_number(x509.random_serial_number()
                                                          ).not_valid_before(datetime.datetime.now(datetime.timezone.utc)
                                                                             ).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
                                                                                               ).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
    critical=False,
).sign(private_key, hashes.SHA256())

# 4. Сохраняем приватный ключ
with open("server.key", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# 5. Сохраняем сертификат
with open("server.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("ГОТОВО! Файлы созданы:")
print("   server.key  — приватный ключ")
print("   server.crt  — самоподписанный сертификат (валиден 1 год)")
print("\nТеперь можно запускать сервер и клиент:")
print("   python server.py")
print("   python client.py")