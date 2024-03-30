import getpass
import sys
from time import sleep, time


import config
from cli_func import timed_validated_sanitized_input, timed_validated_sanitized_input_generator, \
    timed_sanitized_input, inactive_or_malicious, create_user, decrypt_vault, print_decrypted_content_as_dataframe, \
    update_vault, update_tag_none, valid_row_input, update_dataframe, create_first_user
from crypto_func import encrypt_AES
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
        created = create_first_user(username, password)
        if created:
            choice = 'w'
            continue

        # if users exist
        res = decrypt_vault(username, password)
        if res is None:
            create_user(username, password)
            choice = 'w'
            continue

        print('\nUsername is taken. Please try again.')
        choice = 'c'
        sleep(config.secs_until_redirect)
        clear()

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

        res = decrypt_vault(username, password)
        if res is None:
            print('\nInvalid username/password. Please try again.')
            choice = 'l'
            sleep(config.secs_until_redirect)
            clear()
            continue

        print('\nSuccessful login. You are being redirected.')
        choice = 'logged_in'
        sleep(config.secs_until_redirect)
        clear()
        continue

    # logged in menu
    elif choice == 'logged_in':
        clear()
        print(f'\nWelcome {username}. Here is you current password manager list (sorted by website name):')

        res = decrypt_vault(username, password)
        file, salt, tag, nonce, vault_key_bytes, vault_content_decrypted = res

        df_view = print_decrypted_content_as_dataframe(vault_content_decrypted)
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

        update_vault(cipher_text_bytes, salt)
        update_tag_none(salt, new_tag_bytes, new_nonce_bytes)

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

        if not valid_row_input(row_str, df_view):
            continue

        update_dataframe(df_view, row_str, vault_key_bytes, salt)

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
