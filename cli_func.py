import os
import random
import string
import sys
import time

import click
import pandas as pd
from dotenv import dotenv_values

import config
from crypto_func import crng, generate_vault_key, encrypt_AES, decrypt_AES
from general_func import clear


def timed_validated_sanitized_input(input_str: str = 'Enter your choice: ',
                                    redirect_if_malicious: str = 'w',
                                    valid_inputs: list = ['l', 'c', 'e'],
                                    redirect_if_invalid: str = 'w') -> str:
    start_time = time.time()
    choice = input(input_str).lower()

    choice = inactive_or_malicious(choice, start_time, config.secs_until_timeout, redirect_if_malicious)

    if choice != redirect_if_malicious:
        if invalid_menu_input(choice, valid_inputs):
            choice = valid_menu_input(valid_inputs, redirect_if_invalid)

    time.sleep(config.secs_until_redirect)
    clear()
    return choice


def inactive_or_malicious(choice, start_time, secs_until_timeout, redirect_if_malicious):
    if is_inactive(start_time, secs_until_timeout):
        inactivity_exit(secs_until_timeout)

    if is_malicious(choice):
        choice = malicious_redirect(redirect_if_malicious)

    return choice


def is_inactive(start_time, secs_until_timeout):
    return time.time() - start_time > secs_until_timeout


def inactivity_exit(secs_until_timeout):
    clear()
    print('\nProgram is exited due to inactivity.')
    time.sleep(secs_until_timeout)
    sys.exit()


def is_malicious(input_str) -> bool:
    banned = config.banned
    list_malicious = [x in input_str for x in banned]
    return any(list_malicious)


def malicious_redirect(redirect_choice_value: str = 'w'):
    print('\nInvalid inputs. PLease try again.')
    return redirect_choice_value


def invalid_menu_input(input_str, valid_inputs: list) -> bool:
    return input_str not in valid_inputs


def valid_menu_input(valid_inputs: list, redirect_choice_value: str) -> str:
    str_valid_inputs = ', '.join(valid_inputs)
    print(f'\nValid options are: {str_valid_inputs}. Please try again:')
    return redirect_choice_value


def timed_validated_sanitized_input_generator(username_or_password: str = 'username',  # 'username' or 'password
                                              redirect_if_malicious: str = 'w') -> str:
    start_time = time.time()
    choice = input(f'\nEnter {username_or_password} (enter g for random generated {username_or_password}): ')

    choice = inactive_or_malicious(choice, start_time, config.secs_until_timeout, redirect_if_malicious)

    # generate username/password
    while choice.lower() == 'g':
        start_time = time.time()
        choice = suggest_random(username_or_password)
        choice = inactive_or_malicious(choice, start_time, config.secs_until_timeout, redirect_if_malicious)

    # validate choice
    bool_redirect, choice = validate_input_str(choice, redirect_if_malicious)
    if bool_redirect:
        time.sleep(config.secs_until_redirect)

    return choice


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


def random_words_generator():
    generated_str = generate_words(config.nr_words)

    generated_str = random_replacement(generated_str, string.ascii_uppercase, config.n_replace)
    generated_str = random_replacement(generated_str, string.digits, config.n_replace)

    puncs = get_valid_punctuations(config.banned)
    generated_str = random_replacement(generated_str, puncs, config.n_replace)

    return generated_str


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


def validate_input_str(input_str, redirect_if_invalid: str = 'l'):
    bool_redirect = False

    # valid punctuations
    puncs = string.punctuation
    banned = config.banned
    for ban in banned:
        puncs = puncs.replace(ban, '')

    # if too short
    if len(input_str) < 9:
        input_str = str_invalid_redirect_to('Input must be of minimum 9 characters. Please try again.',
                                            redirect_if_invalid)

    # must contain small letters
    elif not any([i in (string.ascii_lowercase + 'æøå') for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    # must contain big letters
    elif not any([i in (string.ascii_uppercase + 'ÆØÅ') for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    # must contain numbers
    elif not any([i in string.digits for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    # must contain punctuations
    elif not any([i in puncs for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    if input_str == redirect_if_invalid:
        bool_redirect = True

    return bool_redirect, input_str


def str_invalid_redirect_to(print_text: str = 'Input must contain small and big letters, numbers and punctuations.',
                            redirect_if_invalid: str = 'l') -> str:
    print(print_text)
    return redirect_if_invalid


def timed_sanitized_input(input_str: str = 'Enter username: ', redirect_if_malicious: str = 'w') -> str:
    start_time = time.time()
    choice = input(input_str)
    choice = inactive_or_malicious(choice, start_time, config.secs_until_timeout, redirect_if_malicious)
    return choice


def create_user(username, password):
    # create user
    clear()
    print('\nYour user is being created. Please wait...')

    # generate unique user salt
    user_salt_bytes = crng(32)

    # generate vault key
    vault_key_bytes = generate_vault_key(username, password, user_salt_bytes, config.iterations, config.dklen)

    # add headers to vault:
    vault_headers = '\nwebsite name:url:username:password'

    # encrypt string to add to vault
    cipher_text_bytes, tag_bytes, nonce_bytes = encrypt_AES(vault_headers, vault_key_bytes)

    # create vault with encryption
    with open(os.path.join(os.pardir, config.folder_vaults, f'{user_salt_bytes.hex()}{config.ext}'),
              'a') as envfile:
        envfile.write(cipher_text_bytes.hex())

    # store unique salt, tag and nonce of user
    with open(os.path.join(os.pardir, config.folder_tagNonce, f'{user_salt_bytes.hex()}{config.ext}'),
              'a') as envfile:
        envfile.write(f'tag_and_nonce={tag_bytes.hex()}:{nonce_bytes.hex()}')

    print(
        f'\nDone! You have {config.secs_until_redirect_creating_user} seconds to write down your login credentials:')
    print(f'Username: {username}')
    print(f'Password: {password}')
    time.sleep(config.secs_until_redirect_creating_user)
    clear()


def decrypt_vault(username, password):
    existing_vaults = os.listdir(os.path.join(os.pardir, config.folder_vaults))

    # check cannot decrypt any existing vaults - meaning login credentials are taken
    for file in existing_vaults:

        # load salt of user i
        salt = bytes.fromhex(file[:-len(config.ext)])

        # load tag and nonce of user i
        env_encrypt = dotenv_values(os.path.join(os.pardir, config.folder_tagNonce, file))
        tag_and_nonce = env_encrypt.get('tag_and_nonce', '')
        tag, nonce = [bytes.fromhex(hex_str) for hex_str in tag_and_nonce.split(':')]

        # load vault of user i
        with open(os.path.join(os.pardir, config.folder_vaults, file), 'r') as envfile:
            vault_content_encrypted = bytes.fromhex(envfile.read())

        # generate vault key
        vault_key_bytes = generate_vault_key(username, password, salt, config.iterations, config.dklen)

        # try to decrypt vault - if successful username and password corresponds to an existing user
        try:
            vault_content_decrypted = decrypt_AES(vault_key_bytes, vault_content_encrypted, tag, nonce)

            return file, salt, tag, nonce, vault_key_bytes, vault_content_decrypted

        # if decryption failed try next file/salt value
        except ValueError:
            continue


def print_decrypted_content_as_dataframe(vault_content_decrypted):
    # print vault content
    lines_list = vault_content_decrypted.split('\n')[1:]
    for i, line in enumerate(lines_list):

        # first line of password manager list is column headers
        if i == 0:
            df_view = pd.DataFrame(columns=line.split(':'))
        else:
            df_view.loc[len(df_view)] = line.split(':')

    df_view.sort_values(['website name'], ignore_index=True, inplace=True)
    print('\n')
    print(df_view)
    return df_view


def update_vault(cipher_text_bytes, salt):  # overwrites file
    with open(os.path.join(os.pardir, config.folder_vaults, f'{salt.hex()}{config.ext}'), 'w') as envfile:
        envfile.write(cipher_text_bytes.hex())


def update_tag_none(salt, new_tag_bytes, new_nonce_bytes):  # overwrites file
    with open(os.path.join(os.pardir, config.folder_tagNonce, f'{salt.hex()}{config.ext}'), 'w') as envfile:
        envfile.write(f'tag_and_nonce={new_tag_bytes.hex()}:{new_nonce_bytes.hex()}')


def valid_row_input(row_str, df_view):
    # must not contain decimals
    if '.' in row_str:
        print('Invalid input. Please try again.')
        time.sleep(config.secs_until_redirect)
        clear()
        return False

    # convert to int
    try:
        row_int = int(row_str)
    except ValueError:
        print('Invalid input. Please try again.')
        time.sleep(config.secs_until_redirect)
        clear()
        return False

    # must equal a row index in the password manager list
    if (row_int > len(df_view) - 1) or (row_int < 0):
        print('Invalid input. Please try again.')
        time.sleep(config.secs_until_redirect)
        clear()
        return False

    return True


def update_dataframe(df_view, row_str, vault_key_bytes, salt):
    row_int = int(row_str)

    # delete row
    df_view = df_view.drop(row_int, axis=0)

    # convert dataframe to stored string format
    df_as_string = '\nwebsite name:url:username:password'  # vault column headers
    for i in range(len(df_view)):
        df_as_string += '\n' + ':'.join(df_view.iloc[i, :])

    # encrypt updated vault
    cipher_text_bytes, new_tag_bytes, new_nonce_bytes = encrypt_AES(df_as_string, vault_key_bytes)

    update_vault(cipher_text_bytes, salt)
    update_tag_none(salt, new_tag_bytes, new_nonce_bytes)


def create_first_user(username, password):
    # load unique user salt (salt = filename)
    existing_vaults = os.listdir(os.path.join(os.pardir, config.folder_vaults))

    # if there are no users
    if not existing_vaults:
        create_user(username, password)
        return True
