# Password Manager
## DON'T USE IT TO STORE ANY REAL DATA.
## Usage
It can be used with GUI or only CLI. The main file is PasswordManager.py, is the file, which is producing the CLI-output and so need to be run if CLI is the wanted Output method.
The PasswordManagerGUI.py file is needed you would like to use the GUI variant. The PasswordManager.py file doesn't need the PasswordManagerGUI file if run as CLI variant, but the PasswordManagerGUI.py file indeed needs the PasswordManager.py file
 
**If you don't have a .txt-database yet, you can create one by creating a .txt file in the Select File popup.
On the first time after creation you need to enter the debug mode.
After that enter the password that you want to set as a master password. After that decrypt it with the just set master password, and you will be good to go.**


**See commit history [here](https://github.com/HuckleberryLovesYou/coding/tree/main/vocational-school/python/PasswordManager)**
# Features
## View
This is the most basic feature in a Password Manager. This is the Section you can view your database.
If the database is empty, the program will tell you.

## Add
The next feature is the add feature.
It can be used to create new passwords.
It is capable to set the title, the username, the password for each entry.
Each entry will have its own unique index as an identifier.
There is no limit in the number of entries.
The only character not allowed is the ':'[column].


A special feature is, that you can also generate passwords. To utilize this function, enter a 'G' into the password entry and hit enter.
After that you can enter the password length of the password to generate (4-inf).
You can specify the which characters should get generated. You can choose between Lower- and Uppercase letters, numbers and special characters.
If no password (except for the 'G' entered before) is specified it's going to generate a password. For that it needs to have a password_length specified.

It will put a new entry at the first free index inbetween all indices.

## Remove
The next feature is the remove feature.
It can be used to delete an entire entry specified by its index viewable in View mode.
It will not ask for a conformation.
The index will be deleted and will never be given to any entry ever again as already mentioned in the Add feature.

## Edit
The edit feature allows you to modify specific fields of an existing entry.
To use this feature, you need to provide the index of the entry you want to edit. After that
specify the field you want to edit, and then enter the new value for that field.

The Entry will still have the same Index after the edit and the entries will still be shown in a rising order.
