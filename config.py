from crypto_func import sha512_hash

secs_until_timeout = 300
secs_until_redirect = 1.5
secs_until_redirect_creating_user = 60

folder_vaults = '_vaults'
folder_tagNonce = '_tagNonce'
ext = '.env'

# PBKDF2
iterations = 100000  # OWASP recommends 600.000 iterations for the algorithm used. This is a demo so we use a lower number for increased speed
dklen = 32  # desired key length in bytes

# malicious
banned = ["'", '"', '<', '>', '/', '\\', ':']  # added ':' since used for storing tag and nonce

# random username generator
nr_words = 4
n_replace = 2
uk_word_list = ['bumblebee', 'heaven', 'although', 'wonder', 'belly button', 'fluffy', 'silky',
                'phenomenal', 'unicorn','fungus', 'queue', 'bequeath', 'mixology', 'bibble', 'berserk',
                'gubbins', 'wabbit', 'brouhaha', 'donnybrook', 'random', 'genious', 'people', 'animal']
