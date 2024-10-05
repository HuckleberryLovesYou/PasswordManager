# Password Manager
## DON'T USE IT TO STORE ANY REAL DATA.
## Usage
It can be used with GUI or CLI. The Executable in the releases is always the GUI variant. If you want to use the CLI variant, you have to download the source.
 
**If you don't have a .txt-database yet, you can create one by creating a .txt file in the Select File popup.
After selecting it, enter the password that you want to set as a master password, and you are good to go.**


**See commit history [here](https://github.com/HuckleberryLovesYou/PasswordManager/branches)**
# Features
## Encryption
The most important at the beginning:
The PasswordManager provides encryption. This encryption is handled by the cryptography module in Python.
This module provides safe encryption depending on the usage. I do not recommend anyone to use this PasswordManager.
It might be insecure, it might be vulnerable to attacks. You can take a look at the code used for encryption yourself [here](https://github.com/HuckleberryLovesYou/PasswordManager/blob/bff3eb0f04a4c916ca5258b17b8e8a082cc5323e/PasswordManagerCryptography.py#L22).
All entries are stored encoded in base64 during runtime and getting encrypted if program is quit using the explicit mode.
All entries are stored in a Plain Text (.txt) file.

## View
This is the mode in which you can view all your entries in the database.

## Add
The next feature is the add feature.
It can be used to create new entries with a title, username and password.
Each entry will have its own unique index as an identifier.
There is no limit in the number of entries.
It will put a new entry at the end of the database with the next free index inbetween all indices in the database.

A special feature is, that you can also generate passwords. To utilize this function, enter a 'G' into the password entry.
After that you can enter the password length of the password to generate (4-inf).
You can specify the which characters should get generated. You can choose between Lower- and Uppercase letters, numbers and special characters.
If no password is specified it's going to generate a password. For that it needs to have a password_length specified.

## Remove
The next feature is the remove feature.
It can be used to delete an entire entry specified by its index viewable in View mode.
It will not ask for a conformation.
The index will be deleted and the entry is lost forever.

## Edit
The edit feature allows you to modify specific fields of an existing entry.
To use this feature, you need to provide the index of the entry you want to edit. After that
specify the field you want to edit, and then enter the new value for that field.

The Entry will still have the same Index after the edit.
