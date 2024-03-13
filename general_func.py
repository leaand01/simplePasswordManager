import ctypes
import hashlib
import os
import secrets
import sys
import time

from Crypto.Cipher import AES

import config
import click
import string
from passlib.hash import pbkdf2_sha512, pbkdf2_sha256
import random


# global counter_welcome
# global counter_create
# global counter_login

# def all_valid_inputs():
#     constrained_input = string.ascii_letters + string.digits + string.punctuation
#     for punc in config.banned:
#         constrained_input = constrained_input.replace(punc, '')
#     return constrained_input


def instanciate_hidden_folder(folder_name: str):
    path_folder = os.path.join(os.pardir, folder_name)

    if not os.path.exists(path_folder):
        os.makedirs(path_folder)
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(path_folder, FILE_ATTRIBUTE_HIDDEN)


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def inactivity_exit(secs_until_timeout):
    print('\nProgram is exited due to inactivity.')
    time.sleep(secs_until_timeout)
    clear()
    sys.exit()

def timed_input(input_str: str ='Enter your choice: '):
    start_time = time.time()
    choice = input(input_str)
    if time.time() - start_time > config.secs_until_timeout:
        print('\nProgram is exited due to inactivity.')
        time.sleep(2)
        clear()
        sys.exit()
    return choice


## testing
# def timed_sanitized_input(input_str = 'Enter your choice: ', redirect_choice_value: str = 'w'):
#     start_time = time.time()
#     choice = input(input_str)
#     if time.time() - start_time > config.secs_until_timeout:
#         print('\nProgram is exited due to inactivity.')
#         time.sleep(2)
#         clear()
#         sys.exit()
#
#     if is_malicious(choice):
#         choice = malicious_redirect(input_str, redirect_choice_value)
#         time.sleep(config.secs_until_redirect)
#         clear()
#     return choice


def timed_validated_sanitized_input(input_str: str = 'Enter your choice: ',
                                    redirect_if_malicious: str = 'w',
                                    valid_inputs: list = ['l', 'c', 'e'], # None means no restrictions in input
                                    redirect_if_invalid: str = 'w') -> str:
    start_time = time.time()
    choice = input(input_str).lower()

    choice = inactive_or_malicious(choice, start_time, config.secs_until_timeout, redirect_if_malicious)

    if choice != redirect_if_malicious:
        if invalid_menu_input(choice, valid_inputs) & (valid_inputs is not None): # TODO: Hvis None ikke brugt så fjern (også i tvivl om virker)
            choice = valid_menu_input(valid_inputs, redirect_if_invalid)

    time.sleep(config.secs_until_redirect)
    clear()
    return choice


def invalid_menu_input(input_str, valid_inputs: list) -> bool:
    return input_str not in valid_inputs


def valid_menu_input(valid_inputs: list, redirect_choice_value: str) -> str:
    str_valid_inputs = ', '.join(valid_inputs)
    print(f'\nValid options are: {str_valid_inputs}. Please try again:')
    return redirect_choice_value



# def valid_input(input_str, valid_inputs: list) -> bool:
#     return input_str in valid_inputs
#
#
# def invalid_input(valid_inputs: list, redirect_choice_value: str) -> str:
#     str_valid_inputs = ', '.join(valid_inputs)
#     print(f'\nValid options are: {str_valid_inputs}. Please try again:')
#     return redirect_choice_value


def is_malicious(input_str) -> bool:
    # banned = ["'", '"', '<', '>', '/', '\\']
    banned = config.banned
    list_malicious = [x in input_str for x in banned]
    return any(list_malicious)


# def malicious_redirect(input_str, redirect_choice_value):
#     if is_malicious(input_str):
#         print('\nSafety precautions prevents you from certain inputs. PLease try again.')
#         return redirect_choice_value

def malicious_redirect(redirect_choice_value: str = 'w'):
    print('\nInvalid inputs. PLease try again.')
    return redirect_choice_value


def username_generator():
    # TODO: implement username generator
    return 'myRandomUsername'


def timed_validated_sanitized_input_generator(username_or_password: str = 'username',  # 'username' or 'password
                                              redirect_if_malicious: str = 'w') -> str:
    # print('\nInput username and strong password')
    start_time = time.time()
    choice = input(f'\nEnter {username_or_password} (enter g for random generated {username_or_password}): ')

    choice = inactive_or_malicious(choice, start_time, config.secs_until_timeout, redirect_if_malicious)

    # generate username/password
    while choice.lower() == 'g':
        start_time = time.time()
        choice = suggest_random(username_or_password)
        # generated_choice, choice = suggest_random(username_or_password)

        choice = inactive_or_malicious(choice, start_time, config.secs_until_timeout, redirect_if_malicious)

    # validate choice
    bool_redirect, choice = validate_input_str(choice, redirect_if_malicious)
    if bool_redirect:
        time.sleep(config.secs_until_redirect)

    return choice


def inactive_or_malicious(choice, start_time, secs_until_timeout, redirect_if_malicious):
    if is_inactive(start_time, secs_until_timeout):
        inactivity_exit(secs_until_timeout)

    if is_malicious(choice):
        choice = malicious_redirect(redirect_if_malicious)

    return choice


def is_inactive(start_time, secs_until_timeout):
    return time.time() - start_time > secs_until_timeout


# def suggest_random(username_or_password: str = 'username'):
#     if username_or_password == 'username':
#         choice = suggest_username()
#         # random_str, choice = suggest_username()
#     else:
#         choice = suggest_password()
#         # random_str, choice = suggest_password()
#
#     return choice
#     # return random_str, choice

def suggest_random(username_or_password: str = 'username'):
    if username_or_password == 'username':
        random_username = random_words_generator()
        print('\nPress enter to keep username. Press g to generate new username or enter you own.')
        choice = click.prompt(text='Enter username', default=random_username)

    else:
        random_password = random_words_generator()
        print('\nPress enter to keep password. Press g to generate new password or enter you own.')
        choice = click.prompt(text='Enter password', default=random_password)

    return choice


def suggest_username():
    random_username = random_words_generator()
    # random_username = random_username_generator()
    print('\nPress enter to keep username. Press g to generate new username or enter you own.')
    return click.prompt(text='Enter username', default=random_username)
    # return random_username, click.prompt(text='Enter username', default=random_username)


# def random_username_generator():
#     # TODO: implement username generator
#     return 'myRandomUsername1#'


def suggest_password():
    random_password = random_password_generator()
    print('\nPress enter to keep password. Press g to generate new password or enter you own.')
    return click.prompt(text='Enter password', default=random_password)
    # return random_password, click.prompt(text='Enter password', default=random_password)


def random_password_generator():
    # TODO: implement password generator
    return 'myNotSoStrongPassword1#'


# def str_invalid_redirect_to(print_text: str = '\nInput must contain small and big letters, numbers and punctuations.',
#                             redirect_if_invalid: str = 'l') -> str:
def str_invalid_redirect_to(print_text: str = 'Input must contain small and big letters, numbers and punctuations.',
        redirect_if_invalid: str = 'l') -> str:
    print(print_text)
    return redirect_if_invalid


def validate_input_str(input_str, redirect_if_invalid: str = 'l'):
    bool_redirect = False

    # valid punctuations
    puncs = string.punctuation
    banned = config.banned
    for ban in banned:
        puncs = puncs.replace(ban, '')


    # too short
    if len(input_str) < 9:
        input_str = str_invalid_redirect_to('Input must be of minimum 9 characters. Please try again.',
                                            redirect_if_invalid)
        # input_str = str_invalid_redirect_to('\nInput must be of minimum 9 characters. Please try again.',
        #                                     redirect_if_invalid)

    # contain small letters
    elif not any([i in (string.ascii_lowercase + 'æøå') for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    # contain big letters
    elif not any([i in (string.ascii_uppercase + 'ÆØÅ') for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    # contains numbers
    elif not any([i in string.digits for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    # contains punctuations
    elif not any([i in puncs for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    if input_str == redirect_if_invalid:
        bool_redirect = True

    return bool_redirect, input_str


def sha512_hash(string_to_hash: str):
    str_to_bytes = string_to_hash.encode('UTF-8')
    hash_object = hashlib.sha512(str_to_bytes)
    return hash_object.hexdigest()


def generate_vault_key(username: str, password: str, salt, iterations, dklen) -> bytes:
  return hashlib.pbkdf2_hmac('sha256', (username + password).encode(), salt, iterations, dklen)


# def generate_vault_key(username: str, password: str, salt, iterations, dklen) -> str: # rounds = iterations
#     return hashlib.pbkdf2_hmac('sha256', (username + password).encode(), salt, iterations, dklen)
#
#     # TODO FIX
    # return pbkdf2_sha256.using(rounds=rounds, salt=crng(32)).hash(username + password) # TODO: try crng(64)
    # return pbkdf2_sha512.using(rounds=rounds, salt=crng(32)).hash(username + password) # cannot take crng(64) as input. Raises ValueError: Incorrect AES key length
    # return pbkdf2_sha512.using(rounds=rounds, salt=crng(64)).hash(username + password)


def crng(nbytes):
    """Cryptographic random number generator

    Returns a random byte string containing nbytes number of bytes.
    """
    random_byte_str = secrets.token_bytes(nbytes)
    return random_byte_str


def verify_vault_key(username: str, password: str, vault_key: bytes):
    if not pbkdf2_sha256.verify(username + password, vault_key):
    # if not pbkdf2_sha512.verify(username + password, vault_key):
        raise ValueError('Something went wrong with encryption of user vault_key.')

# def is_username_taken(username: str) -> bool:
#     is_taken = False
#     existing_usernames = os.listdir(os.path.join(os.pardir, config.folder_vault_keys))
#     if sha512_hash(username) + config.ext in existing_usernames:
#         print('\nUsername is taken. Select new username.')
#         is_taken = True
#
#     return is_taken


def generate_words(nr_words: int = 4):
    generated_str = random.choice(config.uk_word_list)
    for i in range(nr_words-1):
        generated_str += ' ' + random.choice(config.uk_word_list)

    return generated_str


def random_replacement(input_str: str = 'some_text', replace_with: str = string.ascii_uppercase,
                       n_replace: int = 2) -> str:
    input_as_list = list(input_str)
    list_length = len(input_as_list)

    for i in range(n_replace):
        idx = random.randrange(list_length)
        input_as_list[idx] = random.choice(replace_with)

    return ''.join(input_as_list)


def get_valid_punctuations(banned_punctuations: list) -> str:
    puncs = string.punctuation
    for ban in banned_punctuations:
        puncs = puncs.replace(ban, '')

    return puncs


def random_words_generator():
    generated_str = generate_words(config.nr_words)

    generated_str = random_replacement(generated_str, string.ascii_uppercase, config.n_replace)
    generated_str = random_replacement(generated_str, string.digits, config.n_replace)

    puncs = get_valid_punctuations(config.banned)
    generated_str = random_replacement(generated_str, puncs, config.n_replace)

    return generated_str


def timed_sanitized_input(input_str: str = 'Enter username: ', redirect_if_malicious: str = 'w') -> str:
    start_time = time.time()
    choice = input(input_str)
    choice = inactive_or_malicious(choice, start_time, config.secs_until_timeout, redirect_if_malicious)
    return choice


def encrypt_AES(plain_text_str: str, key: bytes):
  cipher = AES.new(key, AES.MODE_GCM)
  cipher_text, tag = cipher.encrypt_and_digest(plain_text_str.encode())
  nonce = cipher.nonce
  return cipher_text, tag, nonce


def decrypt_AES(key: bytes, cipher_text: bytes, tag: bytes, nonce: bytes) -> str:
  decrypt_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
  return decrypt_cipher.decrypt_and_verify(cipher_text, tag).decode()

# def encrypt_AES(data_string: str, key):
#     # header = b'header'
#     cipher = AES.new(key, AES.MODE_GCM)
#     # cipher.update(header)
#
#     cipher_text, tag = cipher.encrypt_and_digest(data_string.encode('UTF-8'))
#     nonce = cipher.nonce
#     return cipher_text, tag, nonce


# def decrypt_AES(key, cipher_text, tag, nonce) -> str:
#     # Decryption
#     # header = b'header'
#     decrypt_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
#     # decrypt_cipher.update(header)
#     return decrypt_cipher.decrypt_and_verify(cipher_text, tag).decode('UTF-8') # TODO: ikke implementeret endnu
