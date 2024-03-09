import sys

import click
from time import sleep
import os
import hashlib
import ctypes
from passlib.hash import pbkdf2_sha512
import secrets
import pandas as pd
from Crypto.Cipher import AES


def encrypt_AES(data_string, key):
    header = b"header"
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)

    cipher_text, tag = cipher.encrypt_and_digest(data_string)
    nonce = cipher.nonce
    return cipher_text, tag, nonce


def decrypt_AES(key, cipher_text, tag, nonce):
    # Decryption
    header = b"header"
    decrypt_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypt_cipher.update(header)
    return decrypt_cipher.decrypt_and_verify(cipher_text, tag) # TODO: ikke implementeret endnu


def crng(nbytes):
    """Cryptographic random number generator

    Returns a random byte string containing nbytes number of bytes.
    """
    random_byte_str = secrets.token_bytes(nbytes)
    return random_byte_str


import dotenv
from dotenv import dotenv_values
from io import StringIO

def welcome_screen_w_input_validation():
    choice = welcome_screen()
    while choice not in ['1', '2']:
        choice = switch_welcome_screen(choice)
    return choice

def welcome_screen():
    print('\nWelcome to your simple offline password manager.')
    print('1) Login')
    print('2) Create user')
    # TODO: add exit/close program function. This should delete all caches info
    return input('Enter you choice: ')


dict_welcome_screen = {'1': '1', '2': '2'}


def switch_welcome_screen(value):
    return dict_welcome_screen.get(value, welcome_wrong_entry())


def welcome_wrong_entry():
    print('\nYou must press 1 or 2. Please try again:')
    print('1) Login')
    print('2) Create user')
    return input('Enter you choice: ')


def create_user():
    print('\nSelect a username and strong password that you can remember!')
    print('If you forget these login credential you will NOT be able to gain access to your password manager account')
    return input('Enter username (enter g for random generated username): ')


def suggest_username():
    random_username = random_username_generator()
    print('\nPress enter to keep username. Press g to generate new username or enter you own.')
    return random_username, click.prompt(text='Enter username', default=random_username)


def random_username_generator():
    # TODO: implement username generator
    return 'myRandomUsername'


def suggest_password():
    random_password = random_password_generator()
    print('\nPress enter to keep password. Press g to generate new password or enter you own.')
    return random_password, click.prompt(text='Enter password', default=random_password)


def random_password_generator():
    # TODO: implement password generator
    return 'myNotSoStrongPassword'


def create_user_setup():
    choice = create_user()  # could be refactored into function called create_user_setup(). maybe later when cleaning code
    if choice.lower() == 'g':
        random_username, choice = suggest_username()
        while choice.lower() == 'g':
            random_username, choice = suggest_username()

    saved_username = choice
    # print(f'\nSelected username: {saved_username}')
    choice = input('\nEnter password (enter g for random generated password): ')
    if choice.lower() == 'g':
        random_password, choice = suggest_password()
        while choice.lower() == 'g':
            random_password, choice = suggest_password()

    saved_password = choice
    print(f'\nYou are about to create a user with these credentials:')
    print(f'Username: {saved_username}')
    print(f'Password: {saved_password}')
    return saved_username, saved_password


def sha512_hash(string_to_hash: str):
    str_to_bytes = string_to_hash.encode('UTF-8')
    hash_object = hashlib.sha512(str_to_bytes)
    return hash_object.hexdigest()


def instanciate_hidden_folder(folder_name: str):
    path_folder = os.path.join(os.pardir, folder_name) # locate hidden folders one level up for a layer of security so now shown in the root directory of app
    # path_folder = os.path.join(os.getcwd(), folder_name)
    if not os.path.exists(path_folder):
        os.makedirs(path_folder)
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(path_folder, FILE_ATTRIBUTE_HIDDEN)
        # ret = ctypes.windll.kernel32.SetFileAttributesW(path_folder, FILE_ATTRIBUTE_HIDDEN)


def generate_vault_key(username: str, password: str, rounds: int):
    return pbkdf2_sha512.using(rounds=rounds, salt=crng(64)).hash(username + password)


def verify_vault_key(username: str, password: str, vault_key: bytes) -> bool:
    if not pbkdf2_sha512.verify(username + password, vault_key):
        raise ValueError('Something went wrong with encryption of user vault_key.')


# Prompt app
# TODO: clear all potential in memmory from last sesseion, like cache, log and other (.idea?). repeat this if supple an exix/close app feature

def main():
    folder_vaults = '_vaults'
    folder_keys = '_keys'
    folder_passwords = '_passwords'
    ext = '.env'
    rounds_PBKDF2 = 10000
    instanciate_hidden_folder(folder_vaults)
    instanciate_hidden_folder(folder_keys)
    instanciate_hidden_folder(folder_passwords)

    choice = welcome_screen_w_input_validation()

    # create user
    while choice == '2': # TODO: potentielt tilføj exit fkt ved opret bruger

        EDIT = True
        while EDIT:
            saved_username, saved_password = create_user_setup()
            choice = click.prompt(text='Do you want to edit your credentials (y/n)', default='y')
            if choice.lower() in ['y', 'yes']:
                print("Let's try again")

            else:
                # TODO: sanitize input to protect from xss
                # validate username and password
                if saved_username == '' or len(saved_password) < 9:
                    print('\nUsername cannot be empty and password must be of minimum 9 characters. Please try again.')
                    sleep(2)
                    continue
                    # TODO: could implement some sort of validation of username or password. like username must not be empty and password must be of x length with big/small letters signs etc

                if saved_username == saved_password:
                    print('\nUsername and password cannot be idential. Please try again.')
                    sleep(2)
                    continue

                # Validate username is not already taken
                existing_usernames = os.listdir(os.path.join(os.pardir, folder_keys))
                if sha512_hash(saved_username) + ext in existing_usernames:
                    print('\nUsername is taken. Select new username.')
                    sleep(2)
                    continue

                EDIT = False
                print('\nYou have successfully created a user. Remember your login credentials:')
                print(f'Username: {saved_username}')
                print(f'Password: {saved_password}')

                # create vault_key for user
                print('\nStoring user data...')
                vault_key = generate_vault_key(saved_username, saved_password, rounds_PBKDF2)
                verify_vault_key(saved_username, saved_password, vault_key)

                # save vault_key
                with open(os.path.join(os.pardir, folder_keys, f'{sha512_hash(saved_username)}{ext}'), 'a') as envfile:
                    envfile.write(sha512_hash('vault_key') + '=' + vault_key)

                # TODO: Store password
                with open(os.path.join(os.pardir, folder_passwords, f'{sha512_hash(saved_username)}{ext}'), 'a') as envfile:
                    # envfile.write('password=' + sha512_hash(saved_password))
                    envfile.write(sha512_hash('password') + '=' + sha512_hash(saved_password))

                del saved_username, saved_password, vault_key, existing_usernames

        print('Done! Your user has been created. You can now login to your account.')
        sleep(2)
        os.system('cls')

        # Redirect to welcome page
        choice = welcome_screen_w_input_validation()


    # login user
    sleep_counter = 1
    existing_usernames = os.listdir(os.path.join(os.pardir, folder_keys))
    existing_passwords = os.listdir(os.path.join(os.pardir, folder_passwords))

    while choice == '1':

        print('\nLogin to your account.') # TODO: muligvis: Login to your account (or press e to exit login and/or close - saving all cache data etc)
        username = input('\nEnter username: ')
        password = input('\nEnter password: ')

        # validate username and password
        if sha512_hash(username) + ext not in existing_usernames:
            print('Username and/or password is invalid. Please try again')
            sleep(2**sleep_counter)
            sleep_counter += 1
            continue

        # validate password
        file_idx = existing_passwords.index(sha512_hash(username) + ext)
        filename = existing_passwords[file_idx]
        env_password = dotenv_values(os.path.join(os.pardir, folder_passwords, filename))

        if sha512_hash(password) != env_password.get(sha512_hash('password'), ''):
            print('Username and/or password is invalid. Please try again')
            sleep(2**sleep_counter)
            sleep_counter += 1
            continue

        os.system('cls')
        LOGGED_IN = True
        while LOGGED_IN:
            print('\nWelcome. What would you like to do?')
            print('a) add password to list')
            print('v) view list')
            #print('d) delete account')
            print('e) logout')
            choice = input('Enter your choice: ').lower()

            # logout
            if choice == 'e':
                os.system('cls')
                main()

            # add to list
            elif choice == 'a':
                print('\nInput website name, url, username, password, notes')
                input_website = input('Enter website name: ')
                input_url = input('Enter url: ')
                input_username = input('Enter username: ')
                input_password = input('Enter password: ')

                # encrypt AES-512-GCM
                existing_usernames = os.listdir(os.path.join(os.pardir, folder_keys))
                file_idx = existing_usernames.index(sha512_hash(username) + ext)
                filename = existing_usernames[file_idx] # NÅET HERTIL
                env_keys = dotenv_values(os.path.join(os.pardir, folder_keys, filename))
                vault_key = env_keys.get('vault_key', '')



                # read existing passwords
                with open(os.path.join(os.pardir, folder_vaults, f'{sha512_hash(username)}{ext}'), 'r') as envfile:
                    lines = envfile.read()

                password_list = f'\n{input_website}:{input_url}:{input_username}:{input_password}'
                # if not empty
                if lines:
                    # load current tag and nonce
                    env_keys = dotenv_values(os.path.join(os.pardir, folder_keys, f'{sha512_hash(saved_username)}{ext}'))
                    tag = env_keys.get(sha512_hash('tag'), '')
                    nonce = env_keys.get(sha512_hash('nonce'), '')

                    # decrypt existing password list
                    current_list = decrypt_AES(vault_key, lines, tag, nonce)

                    # add new password
                    password_list += current_list

                    # # encrypt password list
                    # cipher_text, tag, nonce = encrypt_AES(password_list, vault_key)
                    #
                    # # update tag and nonce in folder with vault key
                    # # with open(os.path.join(os.pardir, folder_keys, f'{sha512_hash(saved_username)}{ext}'), 'r+') as envfile: # TODO: check vault key stays and tag and nonce updates (NOT CHECKED YET)
                    # with open(os.path.join(os.pardir, folder_keys, f'{sha512_hash(saved_username)}{ext}'), 'w') as envfile: # TODO: check vault key stays and tag and nonce updates
                    #     envfile.write(sha512_hash('vault_key') + '=' + vault_key)
                    #     envfile.write(sha512_hash('tag') + '=' + tag)
                    #     envfile.write(sha512_hash('nonce') + '=' + nonce)
                    #
                    # # update password file
                    # with open(os.path.join(os.pardir, folder_passwords, f'{sha512_hash(saved_username)}{ext}'), 'w') as envfile:
                    #     envfile.write(cipher_text)

                # if first added password
                # else:
                # password_list = f'\n{input_website}:{input_url}:{input_username}:{input_password}'

                # encrypt password list
                cipher_text, tag, nonce = encrypt_AES(password_list, vault_key)

                # update tag and nonce in folder with vault key
                # with open(os.path.join(os.pardir, folder_keys, f'{sha512_hash(saved_username)}{ext}'), 'r+') as envfile: # TODO: check vault key stays and tag and nonce updates (NOT CHECKED YET)
                with open(os.path.join(os.pardir, folder_keys, f'{sha512_hash(saved_username)}{ext}'), 'w') as envfile:  # TODO: check vault key stays and tag and nonce updates
                    envfile.write(sha512_hash('vault_key') + '=' + vault_key)
                    envfile.write(sha512_hash('tag') + '=' + tag)
                    envfile.write(sha512_hash('nonce') + '=' + nonce)

                # update password file
                with open(os.path.join(os.pardir, folder_passwords, f'{sha512_hash(saved_username)}{ext}'), 'w') as envfile:
                    envfile.write(cipher_text)

                print('\nYour input have been saved.')
                sleep(1)
                continue

            # view list
            elif choice == 'v':
                # TODO: implementer
                # with open(os.path.join(os.pardir, folder_vaults, f'{sha512_hash(username)}{ext}'), 'r') as envfile:
                # env_vault = dotenv_values(os.path.join(os.pardir, folder_vaults, sha512_hash(username) + ext))
                # env_vault.get('websiteName_and_url_and_username_and_password', '')
                # TODO: Does not work FIX

                # read vault file
                with open(os.path.join(os.pardir, folder_vaults, f'{sha512_hash(username)}{ext}'), 'r') as envfile:
                    lines = envfile.read()

                decrypt_AES(vault_key, lines, tag, nonce)

                df_view = pd.DataFrame(columns=['website', 'url', 'username', 'password']) # TODO: refactor to method
                lines_list = lines.split('\n')[1:]
                for line in lines_list:
                    df_view.loc[len(df_view)] = line.split(':')

                df_view.sort_values(['website'], ignore_index=True, inplace=True)
                print('\n')
                print(df_view)

                print(f'\nWhat would you like to do now?')
                print('b) go back')
                print('d) delete item on list')
                print('e) logout')
                choice = input('Enter your choice: ').lower()

                # go back
                if choice == 'b':
                    os.system('cls')
                    continue # TODO: not tested

                # logout
                elif choice == 'e':
                    os.system('cls')
                    sys.exit(0) # TODO: not test

                elif choice == 'd':
                    print('\nInput row number of the row you want to delete.')
                    choice = input('Enter row number: ')

                    # read vault file
                    with open(os.path.join(os.pardir, folder_vaults, f'{sha512_hash(username)}{ext}'), 'r') as envfile:
                        lines = envfile.read()

                    # delete selected row
                    df_view = pd.DataFrame(columns=['website', 'url', 'username', 'password'])
                    lines_list = lines.split('\n')[1:]
                    for line in lines_list:
                        df_view.loc[len(df_view)] = line.split(':')
                    df_view = df_view.sort_values(['website']).reset_index()
                    idx_to_delete = df_view.iloc[int(choice)]['index']
                    del lines_list[idx_to_delete]

                    # overwrite vault file
                    with open(os.path.join(os.pardir, folder_vaults, f'{sha512_hash(username)}{ext}'), 'w') as envfile:
                        for line in lines_list:
                            envfile.write(f'\n{line}')  # TODO: validate

                    # TODO: redirect to view menu. Add confirmation sure you want to delete (nice to have - vent)
                    continue

                else:
                    # TODO: ensure input equals b r or e
                    print('\Invalid input. Please try again')
                    continue # TODO: not tested

            # elif choice == 'd': # TODO: implement if time (not first priority)
            #     print('\nNot implemented yet')






main()



# # load vault key of specific user
#     env_keys = dotenv_values(os.path.join(os.pardir, folder_keys, f'{sha512_hash(saved_username)}{ext}'))
#     test = env_keys.get('vault_key')
#
#
#
# # TODO: create hidden folder and files (if don't exist). create encrypted vault key. look into locking folders/files. select file format.
#     # NÅET HERTIL
#     # init_file = open(os.path.join(os.pardir, folder_vaults, f'{sha512_hash(saved_username)}.env'), 'a') # TODO rename .env so other extension for further discise (fx .env.secret)
#     # init_file.close()
#     #
#     # init_file = open(os.path.join(os.pardir, '_keys', f'{sha512_hash(saved_username)}.env'), 'a')
#     # init_file.close()
#
#     # with open(os.path.join(os.pardir, folder_vaults, f'{sha512_hash(saved_username)}.env'), 'a') as envfile:
#     #     envfile.write(f"NETWORK_ID = 12345\n")
#     #     envfile.close()
