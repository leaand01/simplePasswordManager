import ctypes
import os


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def instantiate_hidden_folder(folder_name: str):
    path_folder = os.path.join(os.pardir, folder_name)

    if not os.path.exists(path_folder):
        os.makedirs(path_folder)
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(path_folder, FILE_ATTRIBUTE_HIDDEN)
