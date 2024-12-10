#############################################################
#   inspired by 'NeuralNine' on Youtube                     #
#   https://youtu.be/iM3kjbbKHQU?si=5JzFwVoErJ51FYlz        #
#############################################################


#Dependencies:
#PasswordGenerator.py
#PasswordManagerCryptography.py
#customtkinter # can be installed using 'pip install customtkinter'

# DO NOT USE IT TO STORE ANY IMPORTANT DATA
# THIS IS JUST A FUN PROJECT NOT MEANT TO BE USED
import customtkinter
import time
import PasswordManager
import PasswordManagerCryptography
from Config import Config


def get_filepath_gui(): #File selection handled through PasswortManager.get_filepath()
    def call_get_filepath():
        PasswordManager.get_filepath()
        print(f"{Config.is_database_found=}")
        if Config.is_database_found:
            main()
        else:
            database_not_found_error_label = customtkinter.CTkLabel(master=select_file_frame, text="Database not found", font=("Ariel", 28))
            database_not_found_error_label.pack(side="bottom", pady=30, padx=10)
            database_not_found_error_label.after(2500, database_not_found_error_label.destroy)

    select_file_frame = customtkinter.CTkFrame(master=root)
    select_file_frame.pack(pady=20, padx=20, fill="both", expand=True)

    title_label = customtkinter.CTkLabel(master=select_file_frame, text="Password Manger", font=("Ariel", 28))
    title_label.pack(pady=20, padx=20)

    select_file_button = customtkinter.CTkButton(master=select_file_frame, text="Select File...", command=call_get_filepath)
    select_file_button.pack(pady=50, padx=5)



def password_gui():
    def call_convert_to_key():
        PasswordManagerCryptography.convert_master_password_to_key(user_master_password=master_password_entry.get())
        if PasswordManager.is_file_empty(Config.database_filepath) or PasswordManagerCryptography.decrypt_database(Config.database_filepath, Config.key):
            home()
        else:
            password_gui()



    clear_frame()

    master_password_frame = customtkinter.CTkFrame(master=root)
    master_password_frame.pack(pady=20, padx=20, fill="both", expand=True)

    back_button_master_password = customtkinter.CTkButton(master=master_password_frame, text="< Back", command=main)
    back_button_master_password.pack(anchor="nw", padx=5, pady=5)

    title_label_master_password = customtkinter.CTkLabel(master=master_password_frame, text="Password Manager", font=("Ariel", 28))
    title_label_master_password.pack(pady=20, padx=20)

    if Config.is_database_encrypted:
        master_password_entry = customtkinter.CTkEntry(master=master_password_frame, placeholder_text="Enter master password", show="*")
        master_password_entry.pack(padx=10, pady=10)

        master_password_button = customtkinter.CTkButton(master=master_password_frame, text="decrypt", command=call_convert_to_key)
        master_password_button.pack(pady=10, padx=10)
    else:
        master_password_entry = customtkinter.CTkEntry(master=master_password_frame, placeholder_text="Enter master password", show="*", width=200)
        master_password_entry.pack(padx=10, pady=10)

        master_password_button = customtkinter.CTkButton(master=master_password_frame, text="decrypt", command=call_convert_to_key)
        master_password_button.pack(pady=10, padx=10)


def quit_password_gui():
    def call_convert_to_key():
        PasswordManagerCryptography.convert_master_password_to_key(user_master_password=master_password_entry.get())
        PasswordManager.encrypt_and_quit()

    clear_frame()

    master_password_frame = customtkinter.CTkFrame(master=root)
    master_password_frame.pack(pady=20, padx=20, fill="both", expand=True)

    back_button_master_password = customtkinter.CTkButton(master=master_password_frame, text="< Back", command=main)
    back_button_master_password.pack(anchor="nw", padx=5, pady=5)

    title_label_master_password = customtkinter.CTkLabel(master=master_password_frame, text="Password Manager", font=("Ariel", 28))
    title_label_master_password.pack(pady=20, padx=20)

    master_password_entry = customtkinter.CTkEntry(master=master_password_frame, placeholder_text="Enter master password", show="*")
    master_password_entry.pack(padx=10, pady=10)

    master_password_button = customtkinter.CTkButton(master=master_password_frame, text="encrypt", command=call_convert_to_key)
    master_password_button.pack(pady=10, padx=10)



def remove_gui():
    clear_frame()

    def call_remove():
        index_to_remove = index_to_remove_entry.get() #unsure what return type to get from .get()
        if index_to_remove.isdigit():
            index_to_remove = int(index_to_remove)
        else:
            print(f"Got wrong type in remove function. Got {type(index_to_remove)} instead of 'int'")
        PasswordManager.remove(index_to_remove)
        index_to_remove_label = customtkinter.CTkLabel(master=remove_frame, text=f"Removed index: {index_to_remove}")
        index_to_remove_label.pack(side="bottom", padx=10, pady=30)
        index_to_remove_label.after(1500, index_to_remove_label.destroy)
        time.sleep(1.5)
        home()

    clear_frame()
    remove_frame = customtkinter.CTkFrame(master=root)
    remove_frame.pack(pady=20, padx=20, fill="both", expand=True)

    back_add_button = customtkinter.CTkButton(master=remove_frame, text="< Back", command=main)
    back_add_button.pack(anchor="nw", pady=5, padx=5)

    remove_title_label = customtkinter.CTkLabel(master=remove_frame, text="Password Manger", font=("Ariel", 28))
    remove_title_label.pack(pady=20, padx=20)

    index_to_remove_entry = customtkinter.CTkEntry(master=remove_frame, placeholder_text="Index to remove")
    index_to_remove_entry.pack(padx=10, pady=10)

    remove_index_button = customtkinter.CTkButton(master=remove_frame, text="Remove Index", command=call_remove)
    remove_index_button.pack(padx=10, pady=10)


def view_gui():
    clear_frame()
    view_frame = customtkinter.CTkScrollableFrame(master=root)
    view_frame.pack(pady=20, padx=20, fill="both", expand=True)

    back_view_button = customtkinter.CTkButton(master=view_frame, text="< Back", command=main)
    back_view_button.pack(anchor="nw", pady=5, padx=5)

    view_title_label = customtkinter.CTkLabel(master=view_frame, text="Password Manger", font=("Ariel", 28))
    view_title_label.pack(pady=20, padx=20)

    entries = PasswordManager.view()
    if entries is not None:
        lines_count = len(entries)
        show_total_lines_label = customtkinter.CTkLabel(master=view_frame, text=f"Total entries: {lines_count}", fg_color="transparent")
        show_total_lines_label.pack(anchor="ne", pady=30, padx=20)

        for key in entries:
            entry_label = customtkinter.CTkLabel(master=view_frame, text=f"{key}:\tTitle: {entries[key][0]} \tUsername: {entries[key][1]}\tPassword: {entries[key][2]}")
            entry_label.pack(anchor="nw", padx=8, pady=8)
    else:
        show_total_lines_label = customtkinter.CTkLabel(master=view_frame, text=f"Total entries: 0", fg_color="transparent")
        show_total_lines_label.pack(anchor="ne", pady=30, padx=20)

        no_entries_in_database_label = customtkinter.CTkLabel(master=view_frame, text="No entries found in database.")
        no_entries_in_database_label.pack(anchor="nw", padx=8, pady=8)


def add_gui():
    clear_frame()
    add_frame = customtkinter.CTkFrame(master=root)
    add_frame.pack(pady=20, padx=20, fill="both", expand=True)

    back_add_button = customtkinter.CTkButton(master=add_frame, text="< Back", command=main)
    back_add_button.pack(anchor="nw", pady=5, padx=5)

    add_title_label = customtkinter.CTkLabel(master=add_frame, text="Password Manger", font=("Ariel", 28))
    add_title_label.pack(pady=20, padx=20)


    def check_for_generate():
        def call_add(generate: bool = False):
            if generate:
                password_length: int = round(password_length_slider.get())

                password_length_slider.destroy()
                password_length_slider_value_label.destroy()
                password_length_slider_intro_label.destroy()
                generate_and_add_button.destroy()

                index, password = PasswordManager.add(title_entry.get(), username_entry.get(), password=PasswordManager.get_generated_password(password_length))
                index_label = customtkinter.CTkLabel(master=add_frame, text=f"Added password at index {index}, with password {password}")
            else:
                index, password = PasswordManager.add(title=title_entry.get(), username=username_entry.get(), password=password_entry.get())
                index_label = customtkinter.CTkLabel(master=add_frame, text=f"Added password at index {index}")
            index_label.pack(side="bottom", padx=10, pady=30)
            index_label.after(5000, index_label.destroy)
            time.sleep(1.5)
            home()


        password_to_check = password_entry.get()
        if password_to_check[0] == "G":
            password_entry.destroy()
            add_entry_button.pack_forget()
            password_length_slider_value = customtkinter.IntVar()
            password_length_slider_intro_label = customtkinter.CTkLabel(master=add_frame, text="Password Length:")
            password_length_slider_intro_label.pack(padx=10, pady=2)
            password_length_slider_value_label = customtkinter.CTkLabel(master=add_frame, textvariable=password_length_slider_value)
            password_length_slider_value_label.pack(padx=10, pady=10)
            password_length_slider = customtkinter.CTkSlider(master=add_frame, from_=8, to=50, variable=password_length_slider_value)
            password_length_slider.pack(padx=10, pady=10)
            password_length_slider.set(20)

            generate_and_add_button = customtkinter.CTkButton(master=add_frame, text="Generate and add entry", command=lambda: call_add(generate=True))
            generate_and_add_button.pack()
        else:
            call_add()

    title_entry = customtkinter.CTkEntry(master=add_frame, placeholder_text="Title", width=300)
    title_entry.pack(padx=10, pady=10)

    username_entry = customtkinter.CTkEntry(master=add_frame, placeholder_text="Username", width=300)
    username_entry.pack(padx=10, pady=10)

    password_entry = customtkinter.CTkEntry(master=add_frame, placeholder_text="Password / G to generate", width=300)
    password_entry.pack(padx=10, pady=10)

    add_entry_button = customtkinter.CTkButton(master=add_frame, text="Add Entry", command=check_for_generate)
    add_entry_button.pack()


def salt_gui():
    clear_frame()

    salt_frame = customtkinter.CTkFrame(master=root)
    salt_frame.pack(pady=20, padx=20, fill="both", expand=True)

    back_add_button = customtkinter.CTkButton(master=salt_frame, text="< Back", command=main)
    back_add_button.pack(anchor="nw", pady=5, padx=5)

    salt_title_label = customtkinter.CTkLabel(master=salt_frame, text="Password Manger", font=("Ariel", 28))
    salt_title_label.pack(pady=20, padx=20)

    salt = PasswordManagerCryptography.Salt()
    if Config.salt == b"":
        if salt.is_salt_found():
            salt.read_salt_from_file()
            print("Salt found")
            return None
        else:
            salt_not_found_label = customtkinter.CTkLabel(master=salt_frame, text="Salt not found. Please provide it in the same directory as database.")
            salt_not_found_label.pack(side="bottom", pady=30, padx=20)
            salt_not_found_label.after(2000, salt_not_found_label.destroy)

            if PasswordManager.is_file_empty(Config.database_filepath):
                print("Database is empty. Can generate new salt.")
                generate_salt_label = customtkinter.CTkLabel(master=salt_frame, text="Are you sure to generate a new salt?")
                generate_salt_label.pack(anchor="nw", padx=10, pady=10)

                generate_salt_button = customtkinter.CTkButton(master=salt_frame, text="Generate Salt", command=salt.generate_salt)
                generate_salt_button.pack(anchor="nw", padx=10, pady=10)
            else:
                print("Database not empty. Can not generate new salt.")
                salt_not_found_label = customtkinter.CTkLabel(master=salt_frame, text="Can only generate a new salt if database is empty")
                salt_not_found_label.pack(side="bottom", pady=10, padx=10)
    else:
        print("Salt var not empty")





def home():
    def call_encrypt_and_quit():
        if Config.key == b"":
            quit_password_gui()
        else:
            PasswordManager.encrypt_and_quit()

    clear_frame()

    root_frame = customtkinter.CTkFrame(master=root)
    root_frame.pack(pady=20, padx=20, fill="both", expand=True)

    quit_button = customtkinter.CTkButton(master=root_frame, text="Quit", command=call_encrypt_and_quit)
    quit_button.pack(anchor="nw", padx=5, pady=5)

    title_label = customtkinter.CTkLabel(master=root_frame, text="Password Manger", font=("Ariel", 28))
    title_label.pack(pady=20, padx=20)

    view_button = customtkinter.CTkButton(root_frame, text="View", command=view_gui)
    add_button = customtkinter.CTkButton(root_frame, text="Add", command=add_gui)
    remove_button = customtkinter.CTkButton(root_frame, text="Remove", command=remove_gui)

    view_button.pack(side="left", expand=True, padx=10)
    add_button.pack(side="left", expand=True, padx=10)
    remove_button.pack(side="left", expand=True, padx=10)


def clear_frame():
    """Helper function to clear the root frame before switching views."""
    for widget in root.winfo_children():
        print(f"I: Destroyed widget: {widget}")
        widget.destroy()

def main():
    clear_frame()
    if Config.is_database_found:
        print("Step 1: Database found")
        if not PasswordManager.is_file_encrypted(Config.database_filepath):
            print("Step 3: Database is decrypted")
            home()
        else:
            print("Step 4: Database encrypted")
            salt_gui()
            if len(Config.key) == 0:
                password_gui()
            else:
                home()
    else:
        get_filepath_gui()
        print("Step 1: Database not found")


customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()

window_width, windows_height = 1000, 750
root.geometry(f"{window_width}x{windows_height}")


main()
root.mainloop()