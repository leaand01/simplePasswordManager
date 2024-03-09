import ctypes
import os
import time
import config
import sys


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


def valid_input(input_str, valid_inputs: list) -> bool:
    return input_str in valid_inputs


def invalid_input(valid_inputs: list, redirect_choice_value: str) -> str:
    str_valid_inputs = ', '.join(valid_inputs)
    print(f'\nValid options are: {str_valid_inputs}. Please try again:')
    return redirect_choice_value


def is_malicious(input_str) -> bool:
    banned = ["'", '"', '<', '>', ]
    list_malicious = [x in input_str for x in banned]
    return any(list_malicious)


def malicious_redirect(input_str, redirect_choice_value):
    if is_malicious(input_str):
        print('\nSafety precautions prevents you from certain inputs. PLease try again.')
        return redirect_choice_value


def username_generator():
    # TODO: implement username generator
    return 'myRandomUsername'
