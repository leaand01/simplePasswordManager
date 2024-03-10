import ctypes
import os
import sys
import time
import config


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


if not None:
    print('a')

def timed_validated_sanitized_input(input_str: str = 'Enter your choice: ',
                                    redirect_if_malicious: str = 'w',
                                    valid_inputs: list = ['l', 'c'], # None means no restrictions in input
                                    redirect_if_invalid: str = 'w') -> str: # TODO: add input if password
    start_time = time.time()
    choice = input(input_str).lower()

    # Inactivity logout
    if time.time() - start_time > config.secs_until_timeout:
        print('\nProgram is exited due to inactivity.')
        time.sleep(config.secs_until_timeout)
        clear()
        sys.exit()

    # malicious input
    if is_malicious(choice):
        choice = malicious_redirect(redirect_if_malicious)

    # invalid input
    elif invalid_input(choice, valid_inputs) & (valid_inputs is not None):
        choice = valid_input(valid_inputs, redirect_if_invalid)

    time.sleep(config.secs_until_redirect)
    clear()
    return choice


def invalid_input(input_str, valid_inputs: list) -> bool:
    return input_str not in valid_inputs


def valid_input(valid_inputs: list, redirect_choice_value: str) -> str:
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
    print('\nSafety precautions prevents you from certain inputs. PLease try again.')
    return redirect_choice_value


def username_generator():
    # TODO: implement username generator
    return 'myRandomUsername'
