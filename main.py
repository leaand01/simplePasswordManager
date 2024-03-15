import getpass
import sys
from time import sleep, time

import pandas as pd
from dotenv import dotenv_values

import config
from cli_func import timed_validated_sanitized_input, timed_validated_sanitized_input_generator, timed_sanitized_input, \
    inactive_or_malicious
from crypto_func import crng, generate_vault_key, encrypt_AES, decrypt_AES, sha512_hash
from general_func import *


instantiate_hidden_folder(config.folder_vaults)
instantiate_hidden_folder(config.folder_tagNonce)

choice = 'w'

while True:

    # welcome
    if choice.lower() == 'w':

        print('\nWelcome to your simple offline password manager.')
        print('l) Login')
        print('c) Create user')
        print('e) exit')
        choice = timed_validated_sanitized_input('Enter your choice: ',
                                                 'w',
                                                 ['l', 'c', 'e'],
                                                 'w')
        continue

    # create user
    elif choice.lower() == 'c':
        clear()

        print('\nSelect a username and strong password.')
        print('Forgetting these login credential you CANNOT gain access to your password manager account')

        username = timed_validated_sanitized_input_generator('username', redirect_if_malicious='c')
        if username == 'c':
            continue

        password = timed_validated_sanitized_input_generator('password', redirect_if_malicious='c')
        if password == 'c':
            continue

        if username == password:
            print('Username and password must not be identical')
            sleep(config.secs_until_redirect)
            continue

        # check if username+passwords corresponds to an existing user
        # load unique user salt (salt = filename)
        existing_vaults = os.listdir(os.path.join(os.pardir, config.folder_vaults))

        # if there are no users
        if not existing_vaults:

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
                envfile.write(f'{sha512_hash("tag_and_nonce")}={tag_bytes.hex()}:{nonce_bytes.hex()}')

            print(
                f'\nDone! You have {config.secs_until_redirect_creating_user} seconds to write down your login credentials:')
            print(f'Username: {username}')
            print(f'Password: {password}')
            sleep(config.secs_until_redirect_creating_user)
            clear()
            choice = 'w'
            continue

        # if users exist
        else:

            # check cannot decrypt any existing vaults - meaning login credentials are taken
            i = -1
            is_not_existing_user = True
            while is_not_existing_user:

                i += 1
                file = existing_vaults[i]

                # load salt of user i
                salt = bytes.fromhex(file[:-len(config.ext)])

                # load tag and nonce of user i
                env_encrypt = dotenv_values(os.path.join(os.pardir, config.folder_tagNonce, file))
                tag_and_nonce = env_encrypt.get(sha512_hash('tag_and_nonce'), '')
                tag, nonce = [bytes.fromhex(hex_str) for hex_str in tag_and_nonce.split(':')]

                # load vault of user i
                with open(os.path.join(os.pardir, config.folder_vaults, file), 'r') as envfile:
                    vault_content_encrypted = bytes.fromhex(envfile.read())

                # generate vault key
                vault_key_bytes = generate_vault_key(username, password, salt, config.iterations, config.dklen)

                # try to decrypt vault - if successful username and password corresponds to an existing user
                try:
                    vault_content_decrypted = decrypt_AES(vault_key_bytes, vault_content_encrypted, tag, nonce)
                    is_not_existing_user = False

                    print('\nUsername is taken. Please try again.')
                    choice = 'c'
                    sleep(config.secs_until_redirect)
                    clear()

                # if decryption failed try next file/salt value
                except ValueError:

                    if file != existing_vaults[-1]:  # continue looping through filenames
                        continue

                    # if username+password does not match any existing users, the user can be created
                    else:
                        is_not_existing_user = False

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
                        with open(os.path.join(os.pardir, config.folder_vaults, f'{user_salt_bytes.hex()}{config.ext}'), 'a') as envfile:
                            envfile.write(cipher_text_bytes.hex())

                        # store unique salt, tag and nonce of user
                        with open(os.path.join(os.pardir, config.folder_tagNonce, f'{user_salt_bytes.hex()}{config.ext}'), 'a') as envfile:
                            envfile.write(f'{sha512_hash("tag_and_nonce")}={tag_bytes.hex()}:{nonce_bytes.hex()}')

                        print(f'\nDone! You have {config.secs_until_redirect_creating_user} seconds to write down your login credentials:')
                        print(f'Username: {username}')
                        print(f'Password: {password}')
                        sleep(config.secs_until_redirect_creating_user)
                        clear()
                        choice = 'w'
                        continue

            continue

    # login
    elif choice.lower() == 'l':
        print('\nLogin to your account.')

        username = timed_sanitized_input('Enter username: ', 'l')
        if username == 'l':
            continue

        start_time = time()
        password = getpass.getpass('Enter password (not visible): ')  # inputs not visible to user
        password = inactive_or_malicious(password, start_time, config.secs_until_timeout, redirect_if_malicious='l')
        if password == 'l':
            continue

        # check if username+passwords corresponds to an existing user
        # load unique user salt (salt = filename)
        existing_vaults = os.listdir(os.path.join(os.pardir, config.folder_vaults))

        i = -1
        is_not_existing_user = True
        while is_not_existing_user:

            i += 1
            file = existing_vaults[i]

            # load salt of user i
            salt = bytes.fromhex(file[:-len(config.ext)])

            # load tag and nonce of user i
            env_encrypt = dotenv_values(os.path.join(os.pardir, config.folder_tagNonce, file))
            tag_and_nonce = env_encrypt.get(sha512_hash('tag_and_nonce'), '')
            tag, nonce = [bytes.fromhex(hex_str) for hex_str in tag_and_nonce.split(':')]

            # load vault of user i
            with open(os.path.join(os.pardir, config.folder_vaults, file), 'r') as envfile:
                vault_content_encrypted = bytes.fromhex(envfile.read())

            # generate vault key
            vault_key_bytes = generate_vault_key(username, password, salt, config.iterations, config.dklen)

            # try to decrypt vault - if successful username and password corresponds to an existing user
            try:
                vault_content_decrypted = decrypt_AES(vault_key_bytes, vault_content_encrypted, tag, nonce)
                is_not_existing_user = False

                print('\nSuccessful login. You are being redirected.')
                choice = 'logged_in'
                sleep(config.secs_until_redirect)
                clear()

            # if decryption failed try next file/salt value
            except ValueError:

                # if username+password does not match any existing users
                if file == existing_vaults[-1]:
                    print('\nInvalid username/password. Please try again.')
                    is_not_existing_user = False  # exit while loop and repeat login
                    choice = 'l'
                    sleep(config.secs_until_redirect)
                    clear()

                continue
        continue

    # logged in menu
    elif choice == 'logged_in':
        clear()
        print(f'\nWelcome {username}. Here is you current password manager list (sorted by website name):')

        # load vault
        with open(os.path.join(os.pardir, config.folder_vaults, file), 'r') as envfile:
            vault_content_encrypted = bytes.fromhex(envfile.read())

        # load tag and nonce
        env_encrypt = dotenv_values(os.path.join(os.pardir, config.folder_tagNonce, file))
        tag_and_nonce = env_encrypt.get(sha512_hash('tag_and_nonce'), '')
        tag, nonce = [bytes.fromhex(hex_str) for hex_str in tag_and_nonce.split(':')]

        # decrypt vault
        vault_content_decrypted = decrypt_AES(vault_key_bytes, vault_content_encrypted, tag, nonce)

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

        print('\na) add password to list')
        print('d) delete row')
        print('e) exit')

        choice = timed_validated_sanitized_input(input_str='Enter your choice: ',
                                                 redirect_if_malicious='logged_in',
                                                 valid_inputs=['a', 'd', 'e'],
                                                 redirect_if_invalid='logged_in')
        clear()
        continue

    # add to password manager
    elif choice.lower() == 'a':
        clear()
        print('\nInput website name, url, username, password')
        input_website = timed_sanitized_input('\nEnter website name: ', 'a')
        if input_website == 'a':
            print('Input must not equal a. Please try again.')
            sleep(config.secs_until_redirect)
            continue

        input_url = timed_sanitized_input('\nEnter url: ', 'a')
        if input_url == 'a':
            print('Input must not equal a. Please try again.')
            sleep(config.secs_until_redirect)
            continue

        input_username = timed_validated_sanitized_input_generator('username', redirect_if_malicious='a')
        if input_username == 'a':
            continue

        input_password = timed_validated_sanitized_input_generator('password', redirect_if_malicious='a')
        if input_password == 'a':
            continue

        # add inputs to vault
        vault_content_decrypted += f'\n{input_website}:{input_url}:{input_username}:{input_password}'

        # encrypt vault
        cipher_text_bytes, new_tag_bytes, new_nonce_bytes = encrypt_AES(vault_content_decrypted, vault_key_bytes)

        # update vault (overwrite file)
        with open(os.path.join(os.pardir, config.folder_vaults, f'{salt.hex()}{config.ext}'), 'w') as envfile:
            envfile.write(cipher_text_bytes.hex())

        # update tag and nonce (overwrite file)
        with open(os.path.join(os.pardir, config.folder_tagNonce, f'{salt.hex()}{config.ext}'), 'w') as envfile:
            envfile.write(f'{sha512_hash("tag_and_nonce")}={new_tag_bytes.hex()}:{new_nonce_bytes.hex()}')

        choice = 'logged_in'
        clear()
        continue

    # delete row of password manager list
    elif choice.lower() == 'd':

        if df_view.empty:
            print('\nNo rows to delete.')
            sleep(config.secs_until_redirect)
            choice = 'logged_in'
            continue

        print(df_view)
        row_str = timed_sanitized_input('\nEnter row number to delete (press r to return to password manager list): ',
                                        'd')
        if row_str.lower() == 'd':
            clear()
            continue

        # return to password manager list (logged in menu)
        if row_str.lower() == 'r':
            choice = 'logged_in'
            sleep(config.secs_until_redirect)
            clear()
            continue

        # must not contain decimals
        if '.' in row_str:
            print('Invalid input. Please try again.')
            sleep(config.secs_until_redirect)
            clear()
            continue

        # convert to int
        try:
            row_int = int(row_str)
        except ValueError:
            print('Invalid input. Please try again.')
            sleep(config.secs_until_redirect)
            clear()
            continue

        # must equal a row index in the password manager list
        if (row_int > len(df_view) - 1) or (row_int < 0):
            print('Invalid input. Please try again.')
            sleep(config.secs_until_redirect)
            clear()
            continue

        # delete row
        df_view = df_view.drop(row_int, axis=0)

        # convert dataframe to stored string format
        df_as_string = '\nwebsite name:url:username:password'  # vault column headers
        for i in range(len(df_view)):
            df_as_string += '\n' + ':'.join(df_view.iloc[i, :])

        # encrypt updated vault
        cipher_text_bytes, new_tag_bytes, new_nonce_bytes = encrypt_AES(df_as_string, vault_key_bytes)

        # update vault (overwrite file)
        with open(os.path.join(os.pardir, config.folder_vaults, f'{salt.hex()}{config.ext}'), 'w') as envfile:
            envfile.write(cipher_text_bytes.hex())

        # update tag and nonce (overwrite file)
        with open(os.path.join(os.pardir, config.folder_tagNonce, f'{salt.hex()}{config.ext}'), 'w') as envfile:
            envfile.write(f'{sha512_hash("tag_and_nonce")}={new_tag_bytes.hex()}:{new_nonce_bytes.hex()}')

        choice = 'logged_in'
        clear()
        continue

    # logout/exit
    elif choice.lower() == 'e':
        print('\nProgram is exited. Bye.')
        sleep(2)
        clear()
        sys.exit()

    else:
        raise ValueError('You found a bug!')
