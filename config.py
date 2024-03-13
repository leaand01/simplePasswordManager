from cryptography import sha512_hash

secs_until_timeout = 120
secs_until_redirect = 2
secs_until_redirect_creating_user = 8

folder_length = 50
folder_vaults = sha512_hash('_vaults')[:folder_length]
folder_tagNonce = sha512_hash('_tagNonce')[:folder_length]
# folder_vaults = sha512_hash('_vaults')[:folder_length]
# folder_vault_keys = sha512_hash('_keys')[:folder_length]
# folder_master_passwords = sha512_hash('_passwords')[:folder_length]
# folder_vault_keys = sha512_hash('_vault_keys')
# folder_master_passwords = sha512_hash('_master_passwords')
ext = '.env'
# ext = '.env.secret'

# PBKDF2
iterations = 10000
dklen = 32 # desired key length in bytes

# malicious
banned = ["'", '"', '<', '>', '/', '\\', ':'] # added ':' since used for storing tag and nonce


# random username generator
nr_words = 4
n_replace = 2
uk_word_list = ['bumblebee', 'heaven', 'although', 'wonder', 'belly button', 'fluffy', 'silky',
                'phenomenal', 'unicorn','fungus', 'queue', 'bequeath', 'mixology', 'bibble', 'berserk',
                'gubbins', 'wabbit', 'brouhaha', 'donnybrook', 'random', 'genious', 'people', 'animal']


# krypterings nøglen udledt af username, password crng
#
# i stedet for at gemme vault key så gemt salt så kan generere vault key
# har username og password som bruger lige har indtastet. så generer vault key.
# således at nøglen aldrig gemmes på harddisken.
#
# når bruger oprettes så gemt salt for denne bruger. brug denne til ovenstående.
# Ikke fixed salt værdi.
#
#
# ######
#
# ved indtas brugernavn password.
# gem ikke bruger navn og password, checke brugernavn + password + oprettede salt generer den korrekt vault key.
#
# gemmer kun salt.
#
# kan gemme hash a brugernavn. kan bruge hash a bruger navn til at validere login.
# brug evt som navn til mappen.