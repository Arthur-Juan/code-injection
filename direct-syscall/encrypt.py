from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

# === Chave e IV fixos ===
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes
AES_IV  = b"ABCDEF0123456789"                  # 16 bytes

# Entradas e saídas
input_file = "shellcode.bin"
output_file = "encrypted_shellcode.b64"

def encrypt_and_encode():
    # Lê o shellcode bruto
    with open(input_file, "rb") as f:
        shellcode = f.read()

    print(f"[+] Shellcode original: {len(shellcode)} bytes")

    # AES-CBC com PKCS7 padding
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(shellcode, AES.block_size))

    print(f"[+] Shellcode criptografado: {len(encrypted)} bytes")

    # Codifica como base64
    encoded = base64.b64encode(encrypted)

    # Salva
    with open(output_file, "wb") as f:
        f.write(encoded)

    print(f"[+] Shellcode criptografado e codificado salvo em '{output_file}' ({len(encoded)} bytes)")

if __name__ == "__main__":
    encrypt_and_encode()
