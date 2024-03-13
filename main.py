import getpass
import os.path
import string
import sys
import  binascii

import click
import pandas as pd
from dotenv import dotenv_values

from general_func import *
from time import sleep
import config


"""Ændringer der skal laves ift Rasmus:

- ved oprettelse af bruger, gem kun salt generede ved oprettelse af bruger (så unikt per bruger)
- evt gem også sha512 hash a brugernavn (kan bruges som filnavn af vault) 

dvs gem ikke vault_key eller password!!

A) ved oprettelse af bruger generer vault fil med tekst: website page, url, username, password,
   hvor vault filnavnet fx er den unikke salt værdi.


ved login:
- anvend indtastet username og password og loop over vault filer (deres filnavne er salt-værdien).
  Test username+password+salt (filnavn) -> generer vault key -> kan vault filen dekrypteres så er brugeren den rigtige og kan logge ind,
  ellers loop videre til den næste fil.
  Hvis ikke kan dekryptere nogle af filerne så er brugeren ikke oprettet, dvs forkert login oplysninger.
"""






# TODO: ingen exp increasing wait times er implementeret endnu
# global counter_welcome
# global counter_create
# global counter_login


instanciate_hidden_folder(config.folder_vaults)
instanciate_hidden_folder(config.folder_tagNonce)
# instanciate_hidden_folder(config.folder_vault_keys)
# instanciate_hidden_folder(config.folder_master_passwords)

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

        # # Validate username is not already taken # not checked when username is not stored!
        # taken = is_username_taken(username)
        # if taken:
        #     sleep(config.secs_until_redirect)
        #     continue

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
        # print('\nRemember your login credentials:')
        print(f'Username: {username}')
        print(f'Password: {password}')
        sleep(config.secs_until_redirect_creating_user)
        clear()
        choice = 'w'
        continue


        # # create user
        # clear()
        # print('\nRemember your login credentials:')
        # print(f'Username: {username}')
        # print(f'Password: {password}')
        # print('\nYour user is being created. Please wait...')
        #
        # # create vault_key for user
        # vault_key_bytes = generate_vault_key(username, password, crng(32), config.iterations, config.dklen)
        # # vault_key = generate_vault_key(username, password, crng(32), config.iterations_PBKDF2, 32)
        # # vault_key = binascii.hexlify(vault_key).decode()
        # # TODO: problem. kan ikke kryptere vha vault key pga bytes size. ovenfor er den 32, hvordan gemmer jeg den så beholder dette format/størrelse
        #
        # # save vault_key
        # vault_key_hex = vault_key_bytes.hex() # format that can be saved in .env file
        # # key_hex = key.hex()  # format that can be saved in .env file
        # # key_orig = bytes.fromhex(key_hex)
        # # test_path = os.path.join(os.pardir, config.folder_vault_keys, f'TEST{config.ext}')
        # # with open(test_path, 'w') as envfile:
        # #     envfile.write('vault_key' + '=' + key_hex)  # TODO: DETTE VIRKER
        # with open(os.path.join(os.pardir, config.folder_vault_keys, f'{sha512_hash(username)}{config.ext}'), 'a') as envfile:
        #     envfile.write(sha512_hash('vault_key') + '=' + vault_key_hex)
        #
        # # save user (master) password
        # with open(os.path.join(os.pardir, config.folder_master_passwords, f'{sha512_hash(username)}{config.ext}'), 'a') as envfile:
        # # with open(os.path.join(os.pardir, config.folder_master_passwords, f'{sha512_hash(password)}{config.ext}'), 'a') as envfile:
        #     envfile.write(sha512_hash('password') + '=' + sha512_hash(password))
        #
        # del username, password, vault_key_bytes, vault_key_hex
        #
        # print('Done! Redirection to welcome menu...')
        # # print('Done! Your user has been created. You can now login to your account.')
        # # print('Redirection to welcome menu...')
        # choice = 'w'
        # sleep(config.secs_until_redirect_creating_user)
        # clear()


    # login
    elif choice.lower() == 'l':
        print('\nLogin to your account.')  # TODO: muligvis: Login to your account (or press e to exit login and/or close - saving all cache data etc)

        username = timed_sanitized_input('Enter username: ', 'w')
        # start_time = time.time()
        # username = input('Enter username: ')
        # username = inactive_or_malicious(username, start_time, config.secs_until_timeout, redirect_if_malicious='l')
        if username == 'l':
            continue

        start_time = time.time()
        password = getpass.getpass('Enter password (not visible): ') # inputs not visible to user
        password = inactive_or_malicious(password, start_time, config.secs_until_timeout, redirect_if_malicious='l')
        if password == 'l':
            continue

        # NYT
        # check if username+passwords corresponds to an existing user
        # load unique user salt (salt = filename)
        existing_vaults = os.listdir(os.path.join(os.pardir, config.folder_vaults))

        i = -1
        is_not_existing_user = True
        while is_not_existing_user:
        # for i, file in enumerate(existing_vaults): # filename = unique user salt value

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
                # hvis ikke fejler så korrekt input - login og vis password manager
                # print('\nSuccessful login. Please wait while redirecting...')

                # hvis kan dekryptere
                print('\nSuccessful login. You are being redirected.')
                choice = 'logged_in'
                sleep(config.secs_until_redirect)
                clear()


            # if decryption failed try next file/salt value
            except ValueError: # hvilken error smider AES hvis forkert input / ikke kan dekryptere

                # if username+password does not match any existing users
                if file == existing_vaults[-1]:
                    print('\nInvalid username/password. Please try again.')

                continue
        continue


        # # is username created
        # existing_passwords = os.listdir(os.path.join(os.pardir, config.folder_master_passwords))
        # # existing_usernames = os.listdir(os.path.join(os.pardir, config.folder_vault_keys))
        # if sha512_hash(username) + config.ext not in existing_passwords:
        #     print('Username and/or password is invalid. Please try again') # TODO: add exp increasing wait times for login
        #     continue
        #
        # # validate username password
        # file_idx = existing_passwords.index(sha512_hash(username) + config.ext)
        # filename = existing_passwords[file_idx]
        # env_password = dotenv_values(os.path.join(os.pardir, config.folder_master_passwords, filename))
        #
        # if sha512_hash(password) != env_password.get(sha512_hash('password'), ''):
        #     print('Username and/or password is invalid. Please try again') # TODO: add exp increasing wait times for login
        #     continue
        #
        # del password, existing_passwords, file_idx, filename, env_password
        # # del username, password,  existing_passwords, file_idx, filename, env_password
        #
        # print('\nSuccessful login. You are being redirected...')
        # choice = 'logged_in'
        # sleep(config.secs_until_redirect)
        # clear()
        # continue

    # TODO: Nået hertil men tjek at login virker først!
    # logged in menu
    elif choice == 'logged_in':  # change so views list from start and you can just add iten
        clear()
        print(f'\nWelcome {username}. Here is you current password manager list (sorted by website name):')

        # print vault content

        # decrypted vault when validated user login

        # df_view = pd.DataFrame(columns=['website', 'url', 'username', 'password'])  # TODO: refactor to method
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
        print('e) exit')

        choice = timed_validated_sanitized_input(input_str='Enter your choice: ',
                                                 redirect_if_malicious='logged_in',
                                                 valid_inputs=['a', 'e'],
                                                 redirect_if_invalid='logged_in')
        clear()
        continue

        # print('a) add password to list')
        # print('v) view list') # TODO: handle if press view and list is empty
        # print('e) logout')
        # choice = timed_validated_sanitized_input(input_str = 'Enter your choice: ',
        #                                          redirect_if_malicious = 'logged_in',
        #                                          valid_inputs = ['a', 'v', 'e'],
        #                                          redirect_if_invalid = 'logged_in')
        # clear()
        # continue


    # add to password manager
    elif choice.lower() == 'a':
        clear()
        print('\nInput website name, url, username, password')
        input_website = timed_sanitized_input('\nEnter website name: ', 'a')
        if input_website == 'a':
            continue

        input_url = timed_sanitized_input('\nEnter url: ', 'a')
        if input_url == 'a':
            continue

        input_username = timed_validated_sanitized_input_generator('username', redirect_if_malicious='a')
        if input_username == 'a':
            continue

        input_password = timed_validated_sanitized_input_generator('password', redirect_if_malicious='a')
        if input_password == 'a':
            continue


        # NEW
        # add inputs to vault
        vault_content_decrypted += f'\n{input_website}:{input_url}:{input_username}:{input_password}'

        # encrypt vault
        cipher_text_bytes, new_tag_bytes, new_nonce_bytes = encrypt_AES(vault_content_decrypted, vault_key_bytes)

        # update vault (overwrite file)
        with open(os.path.join(os.pardir, config.folder_vaults, f'{salt.hex()}{config.ext}'), 'w') as envfile:
            envfile.write(cipher_text_bytes.hex())

        # udpate tag and nonce (overwrite file)
        with open(os.path.join(os.pardir, config.folder_tagNonce, f'{salt.hex()}{config.ext}'), 'w') as envfile:
            envfile.write(f'{sha512_hash("tag_and_nonce")}={new_tag_bytes.hex()}:{new_nonce_bytes.hex()}')

        choice = 'logged_in'
        clear()
        continue



#
# ##########
#         # string to add to vault
#         str_to_add = f'\n{input_website}:{input_url}:{input_username}:{input_password}'
#
#         # load vault encryption key
#         existing_keys = os.listdir(os.path.join(os.pardir, config.folder_vault_keys))
#         file_idx = existing_keys.index(sha512_hash(username) + config.ext)
#         filename = existing_keys[file_idx]
#         env_keys = dotenv_values(os.path.join(os.pardir, config.folder_vault_keys, filename))
#         # vault_key = env_keys.get(sha512_hash('vault_key'), '')
#         vault_key_bytes = bytes.fromhex(env_keys.get(sha512_hash('vault_key'), ''))
#         # vault_key_hex = env_keys.get(sha512_hash('vault_key'), '')
#         # vault_key_bytes = bytes.fromhex(vault_key_hex)
#
#         # check if vault is created for user
#         vault_exist = os.path.isfile(os.path.join(os.pardir, config.folder_vaults, f'{sha512_hash(username)}{config.ext}'))
#
#
#         # if vault is not empty
#         if vault_exist:
#
#             # load current tag and nonce
#             env_keys = dotenv_values(os.path.join(os.pardir, config.folder_vault_keys, f'{sha512_hash(username)}{config.ext}'))
#             tag_bytes = bytes.fromhex(env_keys.get(sha512_hash('tag'), ''))
#             nonce_bytes = bytes.fromhex(env_keys.get(sha512_hash('nonce'), ''))
#             # tag = env_keys.get(sha512_hash('tag'), '')
#             # nonce = env_keys.get(sha512_hash('nonce'), '')
#
#             # load vault
#             with open(os.path.join(os.pardir, config.folder_vaults, f'{sha512_hash(username)}{config.ext}'), 'r') as envfile:
#                 vault_content_encrypted = envfile.read()
#
#             # decrypt vault
#             vault_content_decrypted = decrypt_AES(vault_key_bytes, vault_content_encrypted, tag_bytes, nonce_bytes)
#             # vault_content_decrypted = decrypt_AES(vault_key, vault_content_encrypted, tag, nonce)
#
#             # add new password
#             vault_content_decrypted += str_to_add
#
#             # encrypt vault
#             cipher_text, tag_bytes, nonce_bytes = encrypt_AES(vault_content_decrypted, vault_key_bytes)
#             # cipher_text, tag, nonce = encrypt_AES(vault_content_decrypted, vault_key)
#
#             # save updated encrypted vault (overwrite file)
#             with open(os.path.join(os.pardir, config.folder_vaults, f'{sha512_hash(username)}{config.ext}'), 'w') as envfile:
#                 envfile.write(cipher_text)
#
#             # update decryption tag and nonce (overwrite file)
#             with open(os.path.join(os.pardir, config.folder_vault_keys, f'{sha512_hash(username)}{config.ext}'), 'w') as envfile:  # TODO: check vault key stays and tag and nonce updates
#                 envfile.write(sha512_hash('vault_key') + '=' + vault_key_bytes.hex())
#                 envfile.write(sha512_hash('tag') + '=' + tag_bytes.hex())
#                 envfile.write(sha512_hash('nonce') + '=' + nonce_bytes.hex())
#
#             del vault_content_encrypted, vault_content_decrypted
#
#         # if vault not yet created
#         else:
#             # encrypt string to add to vault
#             # cipher_text, tag, nonce = encrypt_AES(str_to_add, vault_key_bytes)
#             cipher_text_bytes, tag_bytes, nonce_bytes = encrypt_AES(str_to_add, vault_key_bytes)
#
#             # add tag and nonce to file with vault key
#             # tag_hex = tag_bytes.hex()
#             # nonce_hex = nonce_bytes.hex()
#             with open(os.path.join(os.pardir, config.folder_vault_keys, f'{sha512_hash(username)}{config.ext}'), 'a') as envfile:  # TODO: check vault key stays and tag and nonce updates
#                 envfile.write(sha512_hash('tag') + '=' + tag_bytes.hex())
#                 envfile.write(sha512_hash('nonce') + '=' + nonce_bytes.hex())
#                 # envfile.write(sha512_hash('tag') + '=' + tag_hex)
#                 # envfile.write(sha512_hash('nonce') + '=' + nonce_hex)
#
#             # create vault with encryption
#             # cipher_text_hex = cipher_text_bytes.hex()
#             with open(os.path.join(os.pardir, config.folder_vaults, f'{sha512_hash(username)}{config.ext}'), 'w') as envfile:
#                 envfile.write(cipher_text_bytes.hex())
#                 # envfile.write(cipher_text_hex)
#
#             del cipher_text_bytes
#
#         del (username, input_website, input_url, input_username, input_password, str_to_add, existing_keys, file_idx,
#              filename, vault_key_bytes, env_keys, tag_bytes, nonce_bytes, envfile)
#
#         print('\nYour input have been saved.')
#         print('Please wait while redirection...')
#         choice = 'logged_in'
#         sleep(config.secs_until_redirect)
#         clear()
#         continue


    # # view password manager
    # elif choice.lower() == 'v':
    #     # TODO
    #     raise NotImplementedError

    # logout/exit
    elif choice.lower() == 'e':
        print('\nProgram is exited. Bye.')
        time.sleep(2)
        clear()
        sys.exit()

    else:
        print('Not accounted for')
        sleep(2)
        clear()
        sys.exit()



