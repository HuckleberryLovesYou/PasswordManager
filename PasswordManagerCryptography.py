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



def convert_master_password_to_key(user_master_password: str) -> bytes:
    """Takes string user_master_password and returns the generated key as bytes.
    It is needed for encryption and decryption using encrypt_database() and decrypt_database()"""
    user_master_password = user_master_password.encode()
    salt: bytes = b'\xba\x80\xa0\xfe#\xd59\xe7\xe0\rD\xecU\xa2\xe1\x80'

    kdf: PBKDF2HMAC = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(user_master_password))


def encrypt_database(filename: str, key: bytes) -> bool:
    """Takes path/filename, which can be an absolut path or a relative filepath of the database.
    The key is needed for encryption. It gets generated by convert_master_password_to_key().
    It returns True as a boolean if encryption is successful or returns False as a boolean if decryption failed."""
    try:
        cipher = Fernet(key)

        with open(filename, "rb") as file:
            file_to_encrypt = file.read()

        encrpyted_file = cipher.encrypt(file_to_encrypt)


        with open(filename, "wb") as file:
            file.write(encrpyted_file)

        return True
    except:
        print("Database already encrypted or invalid Key")
        return False

def decrypt_database(filename: str, key: bytes) -> bool:
    """Takes path/filename, which can be an absolut path or a relative filepath of the database.
    The key is needed for decryption. It gets generated by convert_master_password_to_key().
    It returns True as a boolean if decryption is successful or returns False as a boolean if decryption failed."""
    try:
        cipher = Fernet(key)

        with open(filename, "rb") as file:
            file_to_decrypt = file.read()

        decrypted_file = cipher.decrypt(file_to_decrypt)


        with open(filename, "wb") as file:
            file.write(decrypted_file)
        return True
    except:
        print("Database already decrypted or invalid Key")
        return False


def main() -> None:
    # DEBUG
    password: str = input("!!!DEBUG!!!\nEnter master password to encrypt database: ")
    filename: str = input("Enter filename: ")
    # This is needed, if the program is quit - without the use of 'q to quit', while the database is already encrypted
    encrypt_database(filename, convert_master_password_to_key(password))

    # Test password convertion
    print(convert_master_password_to_key(password))
if __name__ == '__main__':
    main()