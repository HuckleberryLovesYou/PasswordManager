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
from os import stat
import PasswordGenerator
from tkinter.filedialog import askopenfilename
import PasswordManagerCryptography
import argparse

global_filename: str = "password.txt"

def get_filepath() -> tuple[str, bool]:
    """
    This function prompts the user to select a .txt file using a gui file dialog imported from tkinter.filedialog
    It then returns the absolute path of the selected database and a boolean with True if the file exists and False otherwise.

    :param: None

    :returns:  tuple[str, bool]: A tuple containing the absolute path of the selected file and a boolean indicating whether the file exists.
    """
    def is_real_file(filepath):
        """
        Checks if the specified path exists and returns a boolean indicating whether it exists or not.

        :param filepath: This is the path that gets checked if it exists.
        :type filepath: str

        :returns: bool: True if the database exists or False if it does not exist.
        """
        if exists(filepath):
            print("Database found")
            return True
        else:
            print("No such database in directory")
            return False

    global global_filename
    global_filename = askopenfilename(title="Select database or create a new one:", filetypes=[("Text files" , "*.txt")])
    return global_filename, is_real_file(global_filename)


def get_entries() -> dict[int, list[str]] | None:
    """
    It opens the file in read mode, gets all lines.
    It splits every line into index, title, username, password by the split character ':'. This is the reason, why no column is allowed in the entries.
    It sorts the entries by their index.

    :return: A dictionary containing the entries, sorted by their keys, which are the indices of the corresponding value. Each entrie is represented as a list of strings, containing the title, username, and password in the value. If the database is empty it returns None.
    :rtype: dict[int, list[str]] | None
    """
    entry_dict = {}
    with open(global_filename, "r") as database:
        database_lines = database.readlines()
        if len(database_lines) == 0:
            print("There are no entries in your database")
            return None
        for line in database_lines:
            index, title, username, password = line.split(":")
            entry_dict[int(index)] = [title, username, password]  # converts index to an integer to be sorted correctly in the next line
    return dict(sorted(entry_dict.items()))  # returns a dictionary sorted be the entire key of type int and the corresponding title, username and password


def view() -> dict[int, list[str]] | None:
    return get_entries()


def add(title: str, username: str, password: str | None = None, password_length: int | None = None, sticky_index: int | None = None, allow_letters: bool = True, allow_numbers: bool = True, allow_special: bool = True, force_characters_occurring_at_least_once: bool = False) -> tuple[int, str] | None:
    """
    Used to add an entry to the database. It will determine the next available index.
    It allows to force an index (e.g. if an edit on an entry is needed, the entry still has the same index as
    before (it will be added at the end of the database, but the database gets sorted by indices at view anyway))

    It can also generate a new password using PasswordGenerator.generate_password() function. This function supports many different  switches listed below.
    If no password is specified, it will generate a new password with a length specified in password_length: int. It needs a length specified, otherwise it will error.


    :param title: Used to specify the title of the new entry
    :type title: str

    :param username: Used to specify the username of the new entry
    :type username: str

    :param password: Used to specify the password of the new entry. If it is not provided, a password will be generated. For that value in password_length is required.
    :type password: str | None

    :param password_length: The length of the generated password. Only used if password is not provided. If password is not provided then password_length is required.
    :type password_length: int | None

    :param sticky_index: The index to assign to the new entry. If not provided, an index will be automatically assigned. Used to keep same index after editing an entry.
    :type sticky_index: int | None

    :param allow_letters: This specifies the switches send to the generate_password() function. Whether to allow letters(lower- and uppercase) in the generated password. Default is True.
    :type allow_letters: bool

    :param allow_numbers: This specifies the switches send to the generate_password() function. Whether to allow numbers in the generated password. Default is True.
    :type allow_numbers: bool

    :param allow_special: This specifies the switches send to the generate_password() function. Whether to allow special characters in the generated password. Default is True.
    :type allow_special: bool

    :param force_characters_occurring_at_least_once: This specifies the switches send to the generate_password() function. Whether to force at least one occurrence of each character type in the generated password. Default is False.
    :type force_characters_occurring_at_least_once: bool

    :return: A tuple containing the index of the new entry and the password set for the new entry. If the entry was not added, returns None.
    :rtype: tuple[int, str] | None

    :except ValueError: If the value in password_length is not convertible to an integer.
    :except Exception: If a column was found in one of the string inputs of this function, since it is the slice character in the database or the password_length was not specified, even though password is not specified as well.
    """
    # checks if new entry has a column in it since it is the slice character.

    # generates a password according to switches if it was not provided.
    if password is None:
        if password_length is None:
            print("The password length must be specified if password is not specified.")
            return None
        else:
            if title.count(":") != 0 or username.count(":") != 0:
                print("Found column in string. Columns are not supported.")
                return None

            try:
                password_length = int(password_length)
                password = PasswordGenerator.generate_password(password_length, letters=allow_letters, numbers=allow_numbers, special=allow_special, characters_occurring_at_least_once=force_characters_occurring_at_least_once)
            except ValueError:
                print(f"Expected type int for password_length but got {type(password_length)} instead")
                return None
    else:
        if title.count(":") != 0 or username.count(":") != 0 or password.count(":") != 0:
            print("Found column in string. Columns are not supported.")
            return None

    # gets index to assign to new entry
    if sticky_index is None:
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
    else:
        index: int = sticky_index

    # write new entry to database
    with open(global_filename, "a") as database:
        # adds a new line character only if an entry is actually added and not only edited
        if sticky_index is None:
            database.write(f"{index}:{title}:{username}:{password}\n")
        else:
            database.write(f"{index}:{title}:{username}:{password}")
    print(f"Entry added at index {index}")
    return index, password



def remove(index_to_remove: int) -> None:
    entries: dict[int, list[str]] | None = get_entries()
    if entries is None:
        print("There are no entries in database")
        return None
    if index_to_remove not in entries.keys():
        print(f"Index {index_to_remove} does not exist")
        return None

    # removes specified entry.
    del entries[index_to_remove]

    # overwrites database with all entries except the removed entry.
    with open(global_filename, "w") as database:
        for index, value in entries.items():
            print(f"{index}:{value[0]}:{value[1]}:{value[2]}", file=database, end="")
    print(f"Index {index_to_remove} removed successfully")


def edit(index_to_edit: int, selected_field: str, new_field_value: str) -> None:
    if new_field_value.count(":") != 0:
        print("Found column in string. Columns are not supported.")
        return None

    entries = get_entries()

    if entries is None:
        print("There are no entries in database")
        return None
    if index_to_edit not in entries.keys():
        print(f"Index {index_to_edit} does not exist")
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
        print("Selected field is not supported. Supported fields: title [t], username [u], password [p]")
        return None
    print("Successfully edited entry")



def main() -> None:
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


    def handle_mode_selection():
        while True:
            if cli_args_given:
                if args.view_boolean:
                    mode = "view"
                elif args.add_boolean:
                    mode = "add"
                elif args.index_to_remove is not None:
                    mode = "remove"
                else:
                    print("No mode specified or invalid mode selected.")
                    quit()
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
            print("No entries found in the database")

        if cli_args_given:
            encrypt_and_quit()


    def handle_add_mode() -> None:
        if cli_args_given:
            if args.generate_password_boolean:
                title = args.title
                username = args.username
                password_length = args.password_length
                index, used_password = add(title, username, password_length)
            else:
                title = args.title
                username = args.username
                password = args.password
                index, used_password = add(title, username, password)
        else:
            title = input("Title: ")
            username = input("Username: ")
            password = input("Password ['G' to generate]: ")
            if password == "G":
                if input("Configure password generation? [y/n]: ").lower() == "y":
                    characters_must_occur_once_bool: bool = False
                    generate_letters: bool = False
                    generate_numbers: bool = False
                    generate_special_characters: bool = False

                    if input("Enable the generation of letters (lowercase and uppercase)? [y/n]: ").lower() == "y":
                        generate_letters = True
                    if input("Enable the generation of numbers? [y/n]: ").lower() == "y":
                        generate_numbers = True
                    if input("Enable the generation of special characters? [y/n]: ").lower() == "y":
                        generate_special_characters = True
                    if input("Force at least one occurrences of above characters? [y/n]: ").lower() == "y":
                        characters_must_occur_once_bool = True

                    if not generate_letters and not generate_numbers and not generate_special_characters:
                        print("Cannot generate a password without characters.")
                        return None

                    while True:
                        generate_password_length: str = input("Enter password length [4-inf]: ")
                        if generate_password_length.isdigit():
                            generate_password_length: int = int(generate_password_length)
                            if generate_password_length > 1:
                                index, used_password = add(title=title, username=username, password_length=int(generate_password_length), allow_letters=generate_letters, allow_numbers=generate_numbers, allow_special=generate_special_characters, force_characters_occurring_at_least_once=characters_must_occur_once_bool)
                                break
                else:
                    generate_password_length: str = input("Enter password length [4-inf]: ")
                    if generate_password_length.isdigit() and len(generate_password_length) >= 2:
                        index, used_password = add(title=title, username=username, password_length=int(generate_password_length))
                    else:
                        print("Please enter a valid password length")
                        return None
            else:
                try:
                    index, used_password = add(title=title, username=username, password=password)
                except TypeError:
                    return None

        if used_password != password:
            print("Your password is set to ", used_password)
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
            print("Please enter a valid number")

        if cli_args_given:
            encrypt_and_quit()


    def handle_edit_mode() -> None:
        index_to_edit = input("Enter index to edit: ")
        if index_to_edit.isdigit():
            index_to_edit = int(index_to_edit)
        else:
            print("Please enter a valid index")
            return None
        selected_field = input("Please select the field you want to edit [title/username/password]: ")
        new_field_value = input("Please enter the new value of the field you want to edit: ")
        edit(index_to_edit, selected_field, new_field_value)


    def handle_cli_args():
        parser = argparse.ArgumentParser(description="Password Manager shortcuts\nCommand example: python PasswordManager.py --master-password password --add --title test --username test --generate-password --length 8")
        parser.add_argument("-m", "--master-password", required=True, action="store", dest="master_password", type=str, help="Enter Master Password for password database")
        parser.add_argument("-v", "--view", action="store_true", dest="view_boolean", help="Used to set the mode to view and view database [Needs --master-password]", required=False)
        parser.add_argument("-a", "--add", action="store_true", dest="add_boolean", help="Used to set the mode to add and add a new entry from database [Needs --master-password]", required=False)
        parser.add_argument("-r", "--remove", action="store", dest="index_to_remove", help="Used to set the mode to remove and specify a index to remove [Needs --master-password]", required=False)
        parser.add_argument("-t", "--title", action="store", dest="title", help="Set title of new entry [Needs --add]", type=str, required=False)
        parser.add_argument("-u", "--username", action="store", dest="username", help="Set username of new entry [Needs --add]", type=str, required=False)
        parser.add_argument("-p", "--password", action="store", dest="password", help="Set password of new entry [Needs --add, except --generate-password is specified]", type=str, required=False)
        parser.add_argument("-g", "--generate-password", action="store_true", dest="generate_password_boolean", help="Specify this to enable password generation [Needs --add]", required=False)
        parser.add_argument("-l", "--length", action="store", dest="length", help="Set the length for password generation for new entry [Needs --generate-password]", type=str, required=False)
        parser.add_argument("-d", "--debug", action="store_true", dest="debug", help="Specify this to enable debug mode [Needs --master-password]", required=False)



        return parser.parse_args(), True


    def handle_database_cryptography():
        while True:
            salt = PasswordManagerCryptography.Salt().get_salt()
            if cli_args_given:
                master_password: str = args.master_password
            else:
                master_password: str = input("Enter Master Password ['d' to enable debug]: ").lower()
            key = PasswordManagerCryptography.convert_master_password_to_key(master_password)

            if cli_args_given:
                if args.debug:
                    print("Enabling Debug Mode")
                    key = PasswordManagerCryptography.convert_master_password_to_key(args.master_password)  # needed because of new password entry
                    PasswordManagerCryptography.encrypt_database(global_filename, key)
                    print("Database encrypted")
                    print("Disabling debug mode")
            else:
                if master_password == "d":
                    print("Enabling Debug Mode")
                    print("Enter password to encrypt the database with")
                    master_password = input("Enter Master Password: ")
                    key = PasswordManagerCryptography.convert_master_password_to_key(master_password)  # needed because of new password entry
                    PasswordManagerCryptography.encrypt_database(global_filename, key)
                    print("File encrypted")
                    print("Disabling debug mode")
            if PasswordManagerCryptography.decrypt_database(global_filename, key):
                print("Database decrypted")
                print("If program is now closed without the use of 'q to quit', the database needs to be repaired in debug mode!")
                return master_password








    cli_args_given = False
    try:
        args, cli_args_given = handle_cli_args()
    except:
        print("No arguments found\nUsing interactive mode instead")



    while True:
        filepath, database_found = get_filepath()
        if database_found:
            if is_file_empty(filepath): # checks if selected database's size is 0 bytes.
                print("Database selected is empty, setting new master password")
                PasswordManagerCryptography.Salt().get_salt()
                if cli_args_given:
                    master_password: str = args.master_password
                else:
                    master_password: str = input("Enter new Master Password: ")
                print(f"Set {master_password} as new master password. Don't forget it!")
            else:
                master_password: str = handle_database_cryptography()
            #handles key generation, if debug mode was used in cli mode
            if cli_args_given and args.debug:
                encrypt_and_quit()

            handle_mode_selection()



if __name__ == '__main__':
    main()