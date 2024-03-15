import random
import string
import sys
import time

import click

import config
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

    # must contains numbers
    elif not any([i in string.digits for i in input_str]):
        input_str = str_invalid_redirect_to(redirect_if_invalid=redirect_if_invalid)

    # must contains punctuations
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
