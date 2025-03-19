import struct

SBOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
]

def gost_substitute(value):
    """Применяет S-блоки к 32-битному значению (4 бита на каждый из 8 блоков)."""
    result = 0
    for i in range(8):
        nibble = (value >> (4 * i)) & 0xF
        result |= (SBOX[i][nibble] << (4 * i))
    return result

def rol32(value, bits):
    """Циклический сдвиг 32-битного числа влево на bits бит."""
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))

def f(x, k):
    """Раундовая функция: (x + k) mod 2^32, S-блок замена и циклический сдвиг на 11 бит."""
    return rol32(gost_substitute((x + k) % 0x100000000), 11)

def get_round_keys(key_parts):
    """
    Формирует список из 32 раундовых ключей:
      - Первые 24 раунда: ключи key_parts повторяются 3 раза,
      - Последние 8 раундов: ключи в обратном порядке.
    """
    return key_parts * 3 + list(reversed(key_parts))

def gost_encrypt_block(block, key_parts):
    n1, n2 = struct.unpack("<II", block)
    round_keys = get_round_keys(key_parts)
    # На каждом раунде используем правую половину (n2)
    for k in round_keys:
        temp = (n2 + k) % 0x100000000
        temp = gost_substitute(temp)
        temp = rol32(temp, 11)
        # Стандартная схема Фейстеля: (n1, n2) = (n2, n1 XOR f(n2, k))
        n1, n2 = n2, n1 ^ temp
    return struct.pack("<II", n1, n2)

def gost_decrypt_block(block, key_parts):
    n1, n2 = struct.unpack("<II", block)
    # Для дешифрования используем обратный порядок ключей
    round_keys = list(reversed(get_round_keys(key_parts)))
    for k in round_keys:
        temp = (n2 + k) % 0x100000000
        temp = gost_substitute(temp)
        temp = rol32(temp, 11)
        n1, n2 = n2, n1 ^ temp
    return struct.pack("<II", n1, n2)

def pkcs7_pad(data, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Неверная длина паддинга.")
    return data[:-pad_len]

DEFAULT_KEY = b'0123456789abcdef0123456789abcdef'

def get_key_parts(key=DEFAULT_KEY):
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for GOST")
    return list(struct.unpack("<8I", key))

def gost_encrypt(data, key=DEFAULT_KEY):
    key_parts = get_key_parts(key)
    padded = pkcs7_pad(data)
    encrypted = b""
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        encrypted += gost_encrypt_block(block, key_parts)
    return encrypted

def gost_decrypt(data, key=DEFAULT_KEY):
    key_parts = get_key_parts(key)
    decrypted = b""
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        decrypted += gost_decrypt_block(block, key_parts)
    return pkcs7_unpad(decrypted)

if __name__ == "__main__":
    a = input("Введите строку: ")
    print("Исходная строка:", a)
    encrypted = gost_encrypt(a.encode("utf-8"))
    print("Зашифрованные данные:", encrypted)
    try:
        decrypted = gost_decrypt(encrypted).decode("utf-8")
    except Exception as e:
        decrypted = f"Ошибка дешифрования: {e}"
    print("Расшифрованная строка:", decrypted)
