#############################################################
#   inspired by 'Tech wit Tim' on Youtube                   #
#   https://youtu.be/NpmFbWO6HPU?si=NUpQHy3AY0X9-qJh&t=4008 #
#############################################################

#Dependencies:
#os
#PasswordGenerator.py
#Cryptography.py
#tkinter

# DO NOT USE IT TO STORE ANY IMPORTANT DATA

from os.path import exists
from os import stat
import PasswordGenerator
from tkinter.filedialog import askopenfilename
import Cryptography
import argparse
import base64
from Config import Config
from sys import argv

def is_file_encrypted(filename) -> bool:
    with open(filename, "r") as file:
        line = file.readline()
        for i in range(len(line)):
            if line[i] == ":":
                # print("Database not encrypted")
                Config.is_database_encrypted = False
                return Config.is_database_encrypted
        # print("File encrypted")
        Config.is_database_encrypted = True
        return Config.is_database_encrypted

def is_file_empty(filename) -> bool:
    return stat(filename).st_size == 0


def is_file_found(filepath) -> bool:
    """
    Checks if the specified path exists and returns a boolean indicating whether it exists or not.

    :param filepath: This is the path that gets checked if it exists.
    :type filepath: str

    :returns: bool: True if the database exists or False if it does not exist.
    """
    if exists(filepath):
        print("I: Database found")
        Config.is_database_found = True
        return Config.is_database_found
    else:
        print("E: No such database in directory")
        return Config.is_database_found


def get_filepath() -> str:
    if Config.database_filepath == "":
        Config.database_filepath = askopenfilename(title="Select database or create a new one:", filetypes=[("Text files", "*.txt")])
        is_file_found(Config.database_filepath)
    return Config.database_filepath

def get_entries() -> dict[int, list[str]] | None:
    """
    It opens the file in read mode, gets all lines.
    It splits every line into index, title, username, password by the split character ':'. This is the reason, why no column is allowed in the entries.
    It sorts the entries by their index.

    :return: A dictionary containing the entries, sorted by their keys, which are the indices of the corresponding value. Each entry is represented as a list of strings, containing the title, username, and password in the value. If the database is empty it returns None.
    :rtype: dict[int, list[str]] | None
    """
    entry_dict = {}
    with open(Config.database_filepath, "r") as database:
        database_lines = database.readlines()
        if len(database_lines) == 0:
            print("I: There are no entries in your database")
            return None
        line_count: int = 0
        try:
            for line in database_lines:
                line_count += 1
                index, title, username, password = line.split(":")

                title_bytes = bytes(title[2:-1].strip(), 'utf-8')
                username_bytes = bytes(username[2:-1].strip(), 'utf-8')
                password_bytes = bytes(password[2:-1].strip(), 'utf-8')

                decoded_title = title_bytes.decode()
                decoded_username = username_bytes.decode()
                decoded_password = password_bytes.decode()
                decoded_title = str(base64.b64decode(decoded_title))
                decoded_username = str(base64.b64decode(decoded_username))
                decoded_password = str(base64.b64decode(decoded_password))
                entry_dict[int(index)] = [decoded_title[2:-1], decoded_username[2:-1], decoded_password[2:-1]]  # converts index to an integer to be sorted correctly in the next line
        except ValueError as e:
            print(f"E: Error occurred while parsing the database: ValueError: {e}")
            print(f"E: Error occurred in line {line_count + 1}")
            return None
    return dict(sorted(entry_dict.items()))  # returns a dictionary sorted be the key of type int and the corresponding title, username and password


def view() -> dict[int, list[str]] | None:
    return get_entries()

def generate_password(password_length: int, generate_letters: bool = True, generate_numbers: bool = True, generate_special: bool = True) -> str:
    """
    It generates a password using PasswordGenerator.generate_password() function. This function supports many different switches listed below.
    If no password_length is specified, it will raise an error.

    :param password_length: The length of the generated password. Only used if password is not provided. If password is not provided then password_length is required.
    :type password_length: int

    :param generate_letters: This specifies the switches send to the generate_password() function. Whether to allow letters(lower- and uppercase) in the generated password. Default is True.
    :type generate_letters: bool

    :param generate_numbers: This specifies the switches send to the generate_password() function. Whether to allow numbers in the generated password. Default is True.
    :type generate_numbers: bool

    :param generate_special: This specifies the switches send to the generate_password() function. Whether to allow special characters in the generated password. Default is True.
    :type generate_special: bool

    :return: It returns the newly generated password as a string. If there was an error it  will return None.
    :rtype: str
    """
    generator = PasswordGenerator.PasswordGenerator()
    generator.configure_generation(password_length, generate_letters, generate_numbers, generate_special)
    return generator.generate()
def add(title: str, username: str, password: str | None = None, sticky_index: int | None = None) -> tuple[int, str] | None:
    """
    Used to add an entry to the database. It will determine the next available index or
    allows to force an index (e.g. if an edit on an entry is needed, the entry still has the same index as before)
    It will ALWAYS add the entry at the end of the database.

    :param title: Used to specify the title of the new entry
    :type title: str

    :param username: Used to specify the username of the new entry
    :type username: str

    :param password: Used to specify the password of the new entry. If it is not provided, a password will be generated. For that value in password_length is required.
    :type password: str | None

    :param sticky_index: The index to assign to the new entry. If not provided, an index will be automatically assigned. Used to keep same index after editing an entry.
    :type sticky_index: int | None

    :return: A tuple containing the index of the new entry and the not encoded password set for the new entry. If the entry was not added, returns None.
    :rtype: tuple[int, str] | None
    """
    if password is None:
        print("Please specify a password.")
        return None

    # gets index to assign to new entry if no sticky index is specified
    if sticky_index is None:
        entries = get_entries()
        if entries is not None:
            existing_indices: list[int] = list(entries.keys())
            for i in range(1, max(existing_indices) + 2):
                if i not in existing_indices:
                    index: int = i
                    break
        else: # Needed if database is empty
            print("I: No indices were found")
            index: int = 1
    else:
        index: int = sticky_index

    #encodes inputs to base64
    encoded_title = base64.b64encode(title.encode('utf-8'))
    encoded_username = base64.b64encode(username.encode('utf-8'))
    encoded_password = base64.b64encode(password.encode('utf-8'))

    # TODO: Find the bug, why it is sometimes adding a new line character and sometimes not!
    # | Code below is temporary fix |
    # adds a new line character to the end of the database file if it doesn't exist
    try:
        with open(Config.database_filepath, "r") as file:
            lines = file.readlines()
        if not lines[-1][-1] == "\n": # '\n' is one character here
            print("T: Didn't found new line character")
            lines[-1] += "\n"
            with open(Config.database_filepath, "w") as file:
                file.writelines(lines)
    except IndexError:
        pass

    # write new entry to database
    with open(Config.database_filepath, "a") as database:
        # adds a new line character only if an entry is actually added and not only edited
        if sticky_index is None:
            database.write(f"{index}:{encoded_title}:{encoded_username}:{encoded_password}\n")
        else:
            database.write(f"{index}:{encoded_title}:{encoded_username}:{encoded_password}")
    print(f"I: Entry added at index {index}")
    return index, password # returns not encoded password



def remove(index_to_remove: int) -> None:
    entries: dict[int, list[str]] | None = get_entries()
    if entries is None:
        print("E: There are no entries in database")
        return None
    if index_to_remove not in entries.keys():
        print(f"E: Index {index_to_remove} does not exist")
        return None

    # removes specified entry.
    del entries[index_to_remove]

    # overwrites database with all entries except the removed entry.
    with open(Config.database_filepath, "w") as database:
        for index, value in entries.items():
            # encodes inputs to base64
            encoded_title = base64.b64encode(value[0].encode('utf-8'))
            encoded_username = base64.b64encode(value[1].encode('utf-8'))
            encoded_password = base64.b64encode(value[2].encode('utf-8'))
            # writes new entry to database
            print(f"{index}:{encoded_title}:{encoded_username}:{encoded_password}", file=database, end="\n")
    print(f"I: Index {index_to_remove} removed successfully")


def edit(index_to_edit: int, selected_field: str, new_field_value: str) -> None:
    entries = get_entries()

    if entries is None:
        print("E: There are no entries in database")
        return None
    if index_to_edit not in entries.keys():
        print(f"E: Index {index_to_edit} does not exist")
        return None

    if selected_field[0].lower() == "t":
        remove(index_to_edit)
        add(sticky_index=index_to_edit, title=new_field_value, username=entries[index_to_edit][1], password=entries[index_to_edit][2])
    elif selected_field[0].lower() == "u":
        remove(index_to_edit)
        add(sticky_index=index_to_edit, title=entries[index_to_edit][0], username=new_field_value, password=entries[index_to_edit][2])
    elif selected_field[0].lower() == "p":
        remove(index_to_edit)
        add(sticky_index=index_to_edit, title=entries[index_to_edit][0], username=entries[index_to_edit][1], password=new_field_value)
    else:
        print("E: Selected field is not supported. Supported fields: title, username, password")
        return None
    print("I: Successfully edited entry")


def encrypt_and_quit(error_message="") -> None:
    """
    Encrypt the password database file using the provided master password.

    If an error message is provided, print it and raise an exception. After that, exit the program.

    :param error_message: An optional error message to be printed before exiting the program.
    :type error_message: str

    :raises: Exception: If an error message is provided.
    """
    if len(error_message) > 0:
        print("Error occurred!")
        raise Exception(f"{error_message}")

    if Cryptography.encrypt_database(Config.database_filepath, Config.key):
        quit("User ended the program")

def main() -> None:
    def handle_mode_selection() -> None:
        while True:
            if cli_args_given:
                if args.view_boolean:
                    mode = "view"
                elif args.add_boolean:
                    mode = "add"
                elif args.index_to_remove is not None:
                    mode = "remove"
                else:
                    print("E: No mode specified or invalid mode selected.")
                    encrypt_and_quit("No mode specified or invalid mode selected.")
            else:
                mode = input("Choose mode [view/add/remove/edit/q to quit]: ").lower()

            if mode == "view":
                handle_view_mode()
            elif mode == "add":
                handle_add_mode()
            elif mode == "remove":
                handle_remove_mode()
            elif mode == "edit":
                handle_edit_mode()
            elif mode == "q":
                encrypt_and_quit()
            else:
                print("Invalid mode.")



    def handle_view_mode() -> None:
        view_dict = view()
        try:
            for key in view_dict.keys():
                print(f"{key}:\t\tTitle: {view_dict[key][0]}\tUsername: {view_dict[key][1]}\tPassword: {view_dict[key][2]}\n")
        except AttributeError:
            print("W: No entries found in the database")

        if cli_args_given:
            encrypt_and_quit()


    def handle_add_mode() -> None:
        if cli_args_given:
            if args.generate_password_boolean:
                title = args.title
                username = args.username
                password_length = input("Enter password length [4-inf]: ")
                if password_length.isdigit():
                    password_length = int(password_length)
                else:
                    return None
                index, set_password = add(title, username, password=generate_password(password_length))
            else:
                title = args.title
                username = args.username
                password = args.password
                index, set_password = add(title, username, password)
        else:
            title = input("Title: ")
            username = input("Username: ")
            password = input("Password ['G' to generate]: ")
            if password == "G":
                if input("Configure password generation? [y/n]: ").lower() == "y":
                    characters_must_occur_once_bool: bool = False
                    generate_letters: bool = False
                    generate_numbers: bool = False
                    generate_special: bool = False

                    if input("Enable the generation of letters (lowercase and uppercase)? [y/n]: ").lower() == "y":
                        generate_letters = True
                    if input("Enable the generation of numbers? [y/n]: ").lower() == "y":
                        generate_numbers = True
                    if input("Enable the generation of special characters? [y/n]: ").lower() == "y":
                        generate_special = True

                    if not generate_letters and not generate_numbers and not generate_special:
                        print("Cannot generate a password without characters.")
                        return None

                    while True:
                        password_length: str = input("Enter password length [4-inf]: ")
                        if password_length.isdigit():
                            password_length: int = int(password_length)
                            if password_length > 1:
                                index, set_password = add(title, username, password=generate_password(password_length, generate_letters, generate_numbers, generate_special))
                                break
                else:
                    password_length: str = input("Enter password length [4-inf]: ")
                    if password_length.isdigit():
                        index, set_password = add(title, username, password=generate_password(int(password_length)))
                    else:
                        print("Please enter a valid password length")
                        return None
            else:
                try:
                    index, set_password = add(title=title, username=username, password=password)
                except TypeError:
                    return None

        print(f"I: Your password is set to: (length: {len(set_password)})", set_password)
        if cli_args_given:
            encrypt_and_quit()


    def handle_remove_mode() -> None:
        if cli_args_given:
            index_to_remove = str(args.index_to_remove)
        else:
            index_to_remove = input("Enter index to delete: ")

        if index_to_remove.isdigit():
            index_to_remove = int(index_to_remove)
            remove(index_to_remove)
        else:
            print("E: Please enter a valid number")

        if cli_args_given:
            encrypt_and_quit()


    def handle_edit_mode() -> None:
        index_to_edit = input("Enter index to edit: ")
        if index_to_edit.isdigit():
            index_to_edit = int(index_to_edit)
        else:
            print("E: Please enter a valid index")
            return None
        selected_field = input("Please select the field you want to edit title [t], username [u], password [p]: ")
        new_field_value = input("Please enter the new value of the field you want to edit: ")
        edit(index_to_edit, selected_field, new_field_value)


    def handle_cli_args():
        parser = argparse.ArgumentParser(description="Password Manager shortcuts\nCommand example: python PasswordManager.py --master-password password --add --title test --username test --generate-password --length 8")
        parser.add_argument("-m", "--master-password", required=True, action="store", dest="master_password", type=str, help="Master password to access the database (required).")
        parser.add_argument("-v", "--view", action="store_true", dest="view_boolean", help="View all saved entries (requires --master-password).")
        parser.add_argument("-a", "--add", action="store_true", dest="add_boolean", help="Add a new entry (requires --master-password).")
        parser.add_argument("-r", "--remove", action="store", dest="index_to_remove", type=int, help="Remove an entry by specifying its index (requires --master-password).")
        parser.add_argument("-t", "--title", action="store", dest="title", type=str, help="Title for the new entry (requires --add).")
        parser.add_argument("-u", "--username", action="store", dest="username", type=str, help="Username for the new entry (requires --add).")
        parser.add_argument("-p", "--password", action="store", dest="password", type=str, help="Password for the new entry (requires --add, unless using --generate-password).")
        parser.add_argument("-g", "--generate-password", action="store_true", dest="generate_password_boolean", help="Automatically generate a password (requires --add).")
        return parser.parse_args()


    def handle_database_cryptography() -> str:
        while True:
            Cryptography.Salt().get_salt()
            if cli_args_given:
                master_password: str = args.master_password
            else:
                master_password: str = input("Enter Master Password: ").lower()
            Cryptography.convert_master_password_to_key(master_password)

            if Cryptography.decrypt_database(Config.database_filepath, Config.key):
                if not cli_args_given:
                    print("I: DO NOT CLOSE THE PROGRAM without the use of 'q to quit' in mode selection!")
                return master_password








    cli_args_given = False

    # Check if any arguments were passed, excluding the program name
    if len(argv) > 1:
        try:
            args = handle_cli_args()
            cli_args_given = True
        except SystemExit:  # This exception is raised when -h or --help is called and help is printed
            quit("I: Exiting. User entered '-h/--help'")
        except Exception as e:
            print(f"E: Error parsing arguments: {e}\nUsing interactive mode instead")
    else:
        print("I: No arguments provided. Using interactive mode.")



    while True:
        filepath = get_filepath()
        if not is_file_found(filepath):
            break
        if is_file_empty(filepath):
            print("I: Database selected is empty, setting new master password")
            Cryptography.Salt().get_salt()
            if cli_args_given:
                master_password: str = args.master_password
            else:
                master_password: str = input("Enter new Master Password: ")
                Cryptography.convert_master_password_to_key(master_password)
            print(f"I: Set {master_password} as new master password. Don't forget it!")
        elif not is_file_encrypted(Config.database_filepath): # master_password is needed for encrypting database the next time
            while True:
                print("I: Since database wasn't encrypted after wrong exiting of the program, you have to enter a master password again,\nwhich will be the new master password used. Please always exit the program with 'q to quit'.")
                master_password1: str = input("Enter Master Password: ")
                master_password2: str = input("Enter Master Password again: ")
                if master_password1 == master_password2:
                    PasswordManagerCryptography.convert_master_password_to_key(master_password1)
                    break
                else:
                    print("E: Passwords do not match.\nPlease try again.")
        else:
            handle_database_cryptography()

        handle_mode_selection()



if __name__ == '__main__':
    main()