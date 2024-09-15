#############################################################
#   inspired by 'Tech wit Tim' on Youtube                   #
#   https://youtu.be/NpmFbWO6HPU?si=NUpQHy3AY0X9-qJh&t=4008 #
#############################################################

#Dependencies:
#os
#PasswordGenerator.py
#PasswordManagerCryptography.py
#tkinter

# DO NOT USE IT TO STORE ANY IMPORTANT DATA

from os.path import exists
import PasswordGenerator
from tkinter.filedialog import askopenfilename
import PasswordManagerCryptography
import argparse

global_filename: str = ""

def get_filepath() -> tuple[str, bool]: #let the user select a .txt-file and writes it into global_filename
    def check_for_file(filepath, set_global_filename=False): #checks if file actually exists (might not be needed)
        if exists(filepath): # imported from os.path
            print("Database found")
            return True
        else:
            print("No such database in directory")
            return False
    global global_filename
    global_filename = askopenfilename(title="Select database or create a new one and use debug mode after that:", filetypes=[("Text files" , "*.txt")])
    return global_filename, check_for_file(global_filename)


def get_entries() -> dict[int, list[str]] | None:
    entry_dict = {}
    with open(global_filename, "r") as passwords_file:
        passwords_file_lines = passwords_file.readlines()
        passwords_file_line_count = len(passwords_file_lines)
        if passwords_file_line_count == 0:
            print("There are no entries in your database")
            return None
        for line in passwords_file_lines:
            index, title, username, password = line.split(":")
            entry_dict[int(index)] = [title, username, password]  # converts index to an integer to be sorted correctly in the next line
    return dict(sorted(entry_dict.items()))  # returns a dictionary sorted be the entire key of type int and the corresponding title, username and password


def view() -> dict[int, list[str]] | None:
    return get_entries()


def add(letters=True, numbers=True, special=True, characters_occurring_at_least_once=False, **kwargs) -> tuple[int, str] | None:
    """If password_length is specified password is overwritten"""
    title: str = kwargs.get("title")
    title_column_count = title.count(":")
    username: str = kwargs.get("username")
    username_column_count = title.count(":")
    password: str = kwargs.get("password")
    password_column_count = title.count(":")
    if title_column_count == 0 and username_column_count == 0 and password_column_count == 0:
        password_length = kwargs.get("password_length")
        if password_length != None:
            try:
                password_length = int(password_length)
                password = PasswordGenerator.generate_password(password_length, letters=letters, numbers=numbers, special=special, characters_occurring_at_least_once=characters_occurring_at_least_once)
            except ValueError:
                raise ValueError(f"Expected type int for password_length but got {type(password_length)} instead")


        entries = get_entries()
        if entries is not None:
            existing_indices: list[int] = list(entries.keys())
            for i in range(1, max(existing_indices) + 2):
                if i not in existing_indices:
                    index: int = i
                    break
        else:
            print("No indices were found")
            index: int = 1

        with open(global_filename, "a") as passwords_file:
            passwords_file.write(f"{index}:{title}:{username}:{password}\n")
        print(f"Entry added at index {index}")
        return index, password
    else:
        raise Exception("Found column in string. Columns are not supported.")



def remove(index_to_remove: int) -> None:
    entries: dict[int, list[str]] | None = get_entries()
    if entries is None:
        print("There are no entries in database")
        return None
    del entries[index_to_remove]
    with open(global_filename, "w") as passwords_file:
        for index, value in entries.items():
            print(f"{index}:{value[0]}:{value[1]}:{value[2]}", file=passwords_file, end="")
    print("Index removed successfully")

def edit(index_to_edit: int, user_input):
    ...

def main():
    def encrypt_and_quit(error_message="") -> None:
        """
        Encrypt the password database file using the provided master password.

        If an error message is provided, print it and raise an exception.
        Finally, exit the program.

        :param error_message: An optional error message to be printed before exiting the program. Default is an empty string.
        :type error_message: str

        :raises: Exception: If an error message is provided.

        :returns: None
        """
        PasswordManagerCryptography.encrypt_database(global_filename, PasswordManagerCryptography.convert_master_password_to_key(master_password))
        print("Database encrypted")
        if len(error_message) > 0:
            print("Error occurred!")
            raise Exception(f"{error_message}")
        exit("User ended the program")


    cli_args_given: bool = False
    try:
        parser = argparse.ArgumentParser(description="Password Manager shortcuts\nCommand example: python PasswordManager.py --master-password password --add --title test --username test --length 8")
        parser.add_argument("-m", "--master-password", required=True, action="store", dest="master_password", type=str, help="Enter Master Password for password database")
        parser.add_argument("-v", "--view", action="store_true", dest="view_boolean", help="Used to set the mode to view and view database [Needs --master-password]", required=False)
        parser.add_argument("-a", "--add", action="store_true", dest="add_boolean", help="Used to set the mode to add and add a new entry from database [Needs --master-password]", required=False)
        parser.add_argument("-r", "--remove", action="store_true", dest="remove_boolean", help="Used to set the mode to remove and remove a entry from database [Needs --master-password]", required=False)
        parser.add_argument("-i", "--index", action="store", dest="index", help="Set index in database to delete [Needs --remove]", type=int, required=False)
        parser.add_argument("-t", "--title", action="store", dest="title", help="Set title of new entry [Needs --add]", type=str, required=False)
        parser.add_argument("-u", "--username", action="store", dest="username", help="Set username of new entry [Needs --add]", type=str, required=False)
        parser.add_argument("-p", "--password", action="store", dest="password", help="Set password of new entry [Needs --add, except --generate-password is specified]", type=str, required=False)
        parser.add_argument("-g", "--generate-password", action="store_true", dest="generate_password_boolean", help="Specify this to enable password generation [Needs --add]", required=False)
        parser.add_argument("-l", "--length", action="store", dest="length", help="Set the length for password generation for new entry [Needs --generate-password]", type=str, required=False)
        parser.add_argument("-d", "--debug", action="store_true", dest="debug", help="Specify this to enable debug mode [Needs --master-password]", required=False)

        args = parser.parse_args()

        cli_args_given = True

    except:
        print("No arguments found\nUsing interactive mode instead")
    while True:
        filepath, file_found = get_filepath()
        if file_found:
            while True:
                if cli_args_given:
                    master_password = args.master_password
                else:
                    master_password = input("Enter Master Password ['d' to enable debug]: ").lower()
                key = PasswordManagerCryptography.convert_master_password_to_key(master_password)
                if cli_args_given:
                    if args.debug:
                        print("Enabling Debug Mode")
                        key = PasswordManagerCryptography.convert_master_password_to_key(args.master_password)  # needed because of new password entry
                        PasswordManagerCryptography.encrypt_database(global_filename, key)
                        print("File encrypted")
                        print("Disabling debug mode")
                        encrypt_and_quit()
                else:
                    if master_password == "d":
                        print("Enabling Debug Mode")
                        print("Enter password to encrypt the file with")
                        master_password = input("Enter Master Password: ")
                        key = PasswordManagerCryptography.convert_master_password_to_key(master_password) #needed because of new password entry
                        PasswordManagerCryptography.encrypt_database(global_filename, key)
                        print("File encrypted")
                        print("Disabling debug mode")
                if PasswordManagerCryptography.decrypt_database(global_filename, key):
                    break
            print("Database decrypted")
            if not cli_args_given:
                print("If program is now closed without the use of 'q to quit', the database needs to be repaired in debug mode!")
            while True:
                if cli_args_given:
                    if args.view_boolean:
                        mode = "view"
                    elif args.add_boolean:
                        mode = "add"
                    elif args.remove_boolean:
                        mode = "remove"
                    else:
                        print("No mode specified")
                        quit()
                else:
                    mode = input("Choose mode [view/add/remove/q to quit]: ").lower()

                if mode == "view":
                    view_dict = view()
                    try:
                        for key in view_dict.keys():
                            print(f"{key}:\t\tTitle: {view_dict[key][0]}\tUsername: {view_dict[key][1]}\tPassword: {view_dict[key][2]}\n")
                    except AttributeError:
                        print("No entries found in the database")

                    if cli_args_given:
                        encrypt_and_quit()
                elif mode == "add":
                    if cli_args_given:
                        if args.generate_password_boolean:
                            title = args.title
                            username = args.username
                            password = "G" #spoof that the password input was "G" to enter password generation, so fewer code changes needed
                        else:
                            title = args.title
                            username = args.username
                            password = args.password
                    else:
                        title = input("Title: ")
                        username = input("Username: ")
                        password = input("Password ['G' to generate]: ")
                    if password == "G":
                        if cli_args_given:
                            configure_password_generation = "n" #spoof that there is no configuration for password generation wanted
                        else:
                            configure_password_generation = input("Configure password generation? [y/n]: ").lower()

                        if configure_password_generation == "y":
                            generate_letters = input("Enable the generation of letters (lowercase and uppercase)? [y/n]: ").lower()
                            generate_numbers = input("Enable the generation of numbers? [y/n]: ").lower()
                            generate_special_characters = input("Enable the generation of special characters? [y/n]: ").lower()

                            characters_must_occur_once_bool: bool = False
                            characters_must_occur_once = input("Force at least one occurrences of above characters? [y/n]: ").lower()
                            if characters_must_occur_once == "y":
                                characters_must_occur_once_bool = True

                            generate_letters_bool: bool = False
                            generate_numbers_bool: bool = False
                            generate_special_characters_bool: bool = False

                            while not generate_letters_bool or not generate_numbers_bool or not generate_special_characters_bool:
                                if generate_letters == "y":
                                    generate_letters_bool = True
                                if generate_numbers == "y":
                                    generate_numbers_bool = True
                                if generate_special_characters == "y":
                                    generate_special_characters_bool = True
                                break

                            while True:
                                generate_password_length = input("Enter password length [8-inf]: ")
                                index, generated_password = add(title=title, username=username, password_length=generate_password_length, letters=generate_letters_bool, numbers=generate_numbers_bool, special=generate_special_characters_bool, characters_occurring_at_least_once=characters_must_occur_once_bool)
                                break

                        else:
                            while True:
                                if cli_args_given:
                                    generate_password_length = args.length
                                else:
                                    generate_password_length = input("Enter password length [8-inf]: ")

                                index, generated_password = add(title=title, username=username, password_length=generate_password_length)
                                break


                    else:
                        index, generated_password = add(title=title, username=username, password=password)
                    if generated_password != password:
                        print("Your password is set to ", generated_password)
                    if cli_args_given:
                        encrypt_and_quit()

                elif mode == "remove":
                    if cli_args_given:
                        index_to_remove = str(args.index)
                    else:
                        index_to_remove = input("Enter index to delete: ")

                    if index_to_remove.isdigit():
                        index_to_remove = int(index_to_remove)
                        remove(index_to_remove)
                    else:
                        print("Please enter a valid number")

                    if cli_args_given:
                        encrypt_and_quit()

                elif mode == "q":
                    encrypt_and_quit()

                else:
                    print("Enter a valid mode")
                    if cli_args_given:
                        encrypt_and_quit()



if __name__ == '__main__':
    main()