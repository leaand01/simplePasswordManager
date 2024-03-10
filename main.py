import string
import sys

import click

from general_func import *
from time import sleep
import config


instanciate_hidden_folder(config.folder_vaults)
instanciate_hidden_folder(config.folder_vault_keys)
instanciate_hidden_folder(config.folder_master_passwords)


choice = 'w'

while True:

    # welcome
    if choice.lower() == 'w':

        print('\nWelcome to your simple offline password manager.')
        print('l) Login')
        print('c) Create user')
        # choice = timed_input()
        # choice = timed_sanitized_input(redirect_choice_value='w')
        choice = timed_validated_sanitized_input('Enter your choice: ',
                                                 'w',
                                                 ['l', 'c'],
                                                 'w')
        # TODO: evt tilføj exp voks wait time her også. Efter x forsøg exit. Samme procedure andre steder
        continue
        # if not valid_input(choice.lower(), ['l', 'c']):
        #     choice = invalid_input(['l', 'c'], 'w')
        #     sleep(config.secs_until_redirect)
        #     clear()
        #     continue
        #
        # # redirect with valid choice
        # clear()
        # continue


    # create user
    elif choice.lower() == 'c':
        # TODO: husk exp voksende sleep ved forkert login

        print('\nSelect a username and strong password.')
        print('Forgetting these login credential you CANNOT gain access to your password manager account')
        # choice = timed_input('Enter username (enter g for random generated username): ')
        choice = timed_validated_sanitized_input('Enter username (enter g for random generated username): ',
                                                 'w',
                                                 None,
                                                 'c')

        # if is_malicious(choice):
        #     choice = malicious_redirect(choice, 'c')
        #     sleep(config.secs_until_redirect)
        #     clear()
        #     continue

        # generate username
        while choice.lower() == 'g':
            print('\nPress enter to keep username. Press g to generate new username or enter your own.')

            start_time = time.time()
            choice = click.prompt(text='Enter username', default=username_generator())
            # Inactivity logout
            if time.time() - start_time > config.secs_until_timeout:
                print('\nProgram is exited due to inactivity.')
                time.sleep(config.secs_until_timeout)
                clear()
                sys.exit()

            # malicious input
            if is_malicious(choice):
                choice = malicious_redirect('w')

            # TODO: potential added feature: validate username strength (not implemented)

            # generate new username
            if choice.lower() == 'g':
                continue


        # if is_malicious(choice):
        #     choice = malicious_redirect(choice, 'c')
        #     sleep(config.secs_until_redirect)
        #     clear()
        #     continue

        # repeat above for password, but different password generator
        print('nået til password')

        # evt lavom således at allerede ved alle input/getpass tjekkes for malicious inputs. fri for at repetere kode.





        




    # login
    elif choice.lower() == 'l':
        # TODO
        raise NotImplementedError

        # ved login brug getpass i stedet for input således at user ikke kan se hvad der skrives
        # from getpass import getpass
        # getpass('Enter you password') # returns a string

    # add to password manager
    elif choice.lower() == 'a':
        # TODO
        raise NotImplementedError

    # view password manager
    elif choice.lower() == 'v':
        # TODO
        raise NotImplementedError

    # logout/exit
    elif choice.lower() == 'e':
        # TODO
        raise NotImplementedError

    else:
        print('Not accounted for')
        sleep(2)
        clear()
        sys.exit()



