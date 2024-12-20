#############################################################
#   inspired by 'Tech wit Tim' on Youtube                   #
#   https://youtu.be/NpmFbWO6HPU?si=NUpQHy3AY0X9-qJh&t=4008 #
#############################################################

#Dependencies:
#base64
#cryptography ## can be installed using 'pip install cryptography'

# DO NOT USE IT TO STORE ANY IMPORTANT DATA
# THIS IS JUST A FUN PROJECT NOT MEANT TO BE USED


from base64 import urlsafe_b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from os import urandom
from os.path import dirname, join, basename, exists
from Config import Config

import PasswordManager

class Salt:
    def __init__(self):
        self.salt: bytes = b""
        self.salt_filename: str = self.get_salt_filepath()
        self.is_salt_found_var: bool = False

    def get_salt(self) -> bytes | None:
        if self.salt != b"":
            Config.salt = self.salt
            return self.salt
        print("I: Salt variable is empty")

        if self.is_salt_found():
            print("I: Salt found. Using it.")
            self.read_salt_from_file()
            return self.salt
        else:
            print("W: Salt not found.")
            print("W: Please provide the salt in the same directory as your password database or generate a new one.")
            if input("Confirm generation [y/n]: ").lower() == "y":
                return self.generate_salt()
            else:
                print("E: not generated salt.")
                return None


    def generate_salt(self) -> bytes:
        self.salt = urandom(16)
        self.write_salt_to_file()
        Config.salt = self.salt
        return self.salt

    def get_salt_filepath(self) -> str:
        self.salt_filename = join(dirname(Config.database_filepath), f"{basename(Config.database_filepath)[:4]}_salt.log")
        Config.salt_filepath = self.salt_filename
        return self.salt_filename

    def is_salt_found(self) -> bool:
        if exists(self.salt_filename):
            self.is_salt_found_var = True
            return True
        else:
            return False

    def read_salt_from_file(self) -> bytes:
        with open(self.salt_filename, "rb") as salt_file:
            self.salt = salt_file.read()
            Config.salt = self.salt
        return self.salt

    def write_salt_to_file(self):
        with open(self.salt_filename, "wb") as salt_file:
            salt_file.write(self.salt)
        print("I: Finished writing salt")



def convert_master_password_to_key(user_master_password: str) -> bytes:
    """Takes string user_master_password and returns the generated key as bytes.
    It is needed for encryption and decryption using encrypt_database() and decrypt_database()

    The key generated gets stored in Config.key: bytes, and also returned by the function.
    """
    user_master_password = user_master_password.encode()

    kdf: PBKDF2HMAC = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=Salt().get_salt(),
        iterations=100000,
        backend=default_backend()
    )
    generated_key = urlsafe_b64encode(kdf.derive(user_master_password))
    if len(generated_key) == 0:
        print("E: The Key generated by convert_master_password_to_key() has a length of 0.")

    # Storing key in Config.key
    Config.key = generated_key

    return generated_key


def encrypt_database(filepath: str = Config.database_filepath, key: bytes = Config.key) -> bool:
    """Takes path/filename, which can be an absolut path or a relative filepath of the database.
    The key is needed for encryption. It gets generated by convert_master_password_to_key().
    It returns True as a boolean if encryption is successful or returns False as a boolean if decryption failed."""

    try:
        cipher = Fernet(key)

        with open(filepath, "rb") as database:
            database_to_encrypt = database.read()

        encrpyted_database = cipher.encrypt(database_to_encrypt)


        with open(filepath, "wb") as file:
            file.write(encrpyted_database)
        print("I: Database encrypted")
        return True
    except:
        print("W: Database encryption failed")
        if PasswordManager.is_file_encrypted(Config.database_filepath):
            print("I: Database already encrypted")
        else:
            if len(key) == 0:
                print("E: Key is empty.")
            else:
                print(f"E: Invalid Key with key= {key}")
        return False

def decrypt_database(database_filepath: str, key: bytes) -> bool:
    """Takes path/filename, which can be an absolut path or a relative filepath of the database.
    The key is needed for decryption. It gets generated by convert_master_password_to_key().
    It returns True as a boolean if decryption is successful or returns False as a boolean if decryption failed."""

    try:
        cipher = Fernet(key)

        with open(database_filepath, "rb") as database:
            database_to_decrypt = database.read()

        decrypted_database = cipher.decrypt(database_to_decrypt)


        with open(database_filepath, "wb") as database:
            database.write(decrypted_database)
        print("I: Database encrypted")
        return True
    except:
        print("W: Database decryption failed")

        if len(database_filepath) == 0:
            print("E: Filepath is empty.")
        if database_filepath != Config.database_filepath:
            print(f"W: The database filepath passed to function ({database_filepath}) is not the same as the database filepath stored in Config.database_filepath ({Config.database_filepath}).")
        if len(key) == 0:
            print("E: Key is empty.")
        if key != Config.key:
            print(f"W: The key passed to function ({key}) is not the same as the key stored in Config.key ({Config.key}).")

        if not PasswordManager.is_file_encrypted(Config.database_filepath):
            print("I: Database already decrypted")
        else:
            if len(key) == 0:
                print("E: Key is empty.")
            else:
                print(f"E: Invalid Key with key= {key}")
        return False


def main() -> None:
    pass
    # password: str = input("!!!DEBUG!!!\nEnter master password to encrypt database: ")
    # PasswordManager.get_filepath()
    # print(PasswordManager.get_global_filename())
    # print(PasswordManager.is_file_empty(PasswordManager.get_global_filename()))
    # salt = Salt()
    # print(salt.get_salt())
    # This is needed, if the program is quit - without the use of 'q to quit', while the database is already encrypted
    # encrypt_database(filename, convert_master_password_to_key(password))
    # Test password convertion
    # print(convert_master_password_to_key(password))
if __name__ == '__main__':
    main()