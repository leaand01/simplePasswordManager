from cryptography import sha512_hash

secs_until_timeout = 60
secs_until_redirect = 1
secs_until_redirect_creating_user = 8

folder_length = 50
folder_vaults = sha512_hash('_vaults')[:folder_length]
folder_tagNonce = sha512_hash('_tagNonce')[:folder_length]
ext = '.env'

# PBKDF2
iterations = 10000
dklen = 32  # desired key length in bytes

# malicious
banned = ["'", '"', '<', '>', '/', '\\', ':']  # added ':' since used for storing tag and nonce

# random username generator
nr_words = 4
n_replace = 2
uk_word_list = ['bumblebee', 'heaven', 'although', 'wonder', 'belly button', 'fluffy', 'silky',
                'phenomenal', 'unicorn','fungus', 'queue', 'bequeath', 'mixology', 'bibble', 'berserk',
                'gubbins', 'wabbit', 'brouhaha', 'donnybrook', 'random', 'genious', 'people', 'animal']
