import hashlib
import secrets

from Crypto.Cipher import AES


def crng(nbytes: int) -> bytes:
    """Cryptographic random number generator

    Returns a random byte string containing nbytes number of bytes.
    """
    random_byte_str = secrets.token_bytes(nbytes)
    return random_byte_str


def generate_vault_key(username: str, password: str, salt, iterations, dklen) -> bytes:
  return hashlib.pbkdf2_hmac('sha256', (username + password).encode(), salt, iterations, dklen)


def encrypt_AES(plain_text_str: str, key: bytes):
  cipher = AES.new(key, AES.MODE_GCM)
  cipher_text, tag = cipher.encrypt_and_digest(plain_text_str.encode())
  nonce = cipher.nonce
  return cipher_text, tag, nonce


def decrypt_AES(key: bytes, cipher_text: bytes, tag: bytes, nonce: bytes) -> str:
  decrypt_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
  return decrypt_cipher.decrypt_and_verify(cipher_text, tag).decode()


def sha512_hash(string_to_hash: str):
    str_to_bytes = string_to_hash.encode('UTF-8')
    hash_object = hashlib.sha512(str_to_bytes)
    return hash_object.hexdigest()
