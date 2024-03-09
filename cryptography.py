import hashlib


def sha512_hash(string_to_hash: str):
    str_to_bytes = string_to_hash.encode('UTF-8')
    hash_object = hashlib.sha512(str_to_bytes)
    return hash_object.hexdigest()
