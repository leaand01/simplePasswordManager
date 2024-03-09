from cryptography import sha512_hash

secs_until_timeout = 30
secs_until_redirect = 2


folder_vaults = sha512_hash('_vaults')
folder_vault_keys = sha512_hash('_vault_keys')
folder_master_passwords = sha512_hash('_master_passwords')
ext = '.env.secret'

rounds_PBKDF2 = 10000
