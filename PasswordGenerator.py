from random import choice, randint
from string import ascii_letters
from string import digits
from string import punctuation
# DO NOT USE IT TO STORE ANY IMPORTANT DATA
# THIS IS JUST A FUN PROJECT NOT MEANT TO BE USED

def generate_password(password_length: int, letters=True, numbers=True, special=True, characters_occurring_at_least_once=True) -> str:
    """
    Generates a random password based on the given parameters. It is using the random.randint method of the random module.
    The chances of generating a letter, number, or special are equal. The chances for each character in its own specification are equal as well.
    If characters_occurring_at_least_once is True, it also checks for the minimum required length. The minimum required length depends on the specified criteria in the function call.
    It starts at 0. The amount of characters added to the minimum required length is documented below at each parameter.

    If characters_occurring_at_least_once is False, the minimum required length is 1.

    :param password_length: The desired length of the password.
    :param letters: Whether to include letters in the password. Default is True. Adds 2 to the minimum required length.
    :param numbers: Whether to include numbers in the password. Default is True. Adds 1 to the minimum required length.
    :param special: Whether to include special characters in the password. Default is True. Adds 1 to the minimum required length.
    :param characters_occurring_at_least_once: Whether to ensure that each character type (lowercase letter, uppercase letter, numbers, special) occurs at least once in the password. Default is True.

    :return: A random password that meets the specified criteria.

    :raises Exception: If the password length is less than the minimum required length. The minimum required length changes depending on the specified criteria in the function call. If no character types are selected (letters, numbers, special) it raises an exception as well.
    """
    def is_character_occurring_at_least_once(password_to_check) -> bool:
        if letters:
            is_character_lowercase: bool = False
            is_character_uppercase: bool = False

            for character in password_to_check:
                if character.islower():
                    if character in ascii_letters:
                        is_character_lowercase = True
                else:
                    if character in ascii_letters:
                        is_character_uppercase = True

            if not is_character_lowercase or not is_character_uppercase:
                print("No upper- or lower-case characters")
                return False

        if numbers:
            is_character_number: bool = False
            for character in password_to_check:
                if character in digits:
                    is_character_number = True
            if not is_character_number:
                print("No numbers")
                return False


        if special:
            is_character_special: bool = False
            for character in password_to_check:
                if character in punctuation:
                    is_character_special = True
            if not is_character_special:
                print("No special character")
                return False

        return True


    def generate() -> str:
        password = ""
        while password_length > len(password):
            list_choice = choice(["letters", "numbers", "special"])
            if list_choice == "letters":
                if letters:
                    character = ascii_letters[randint(0, len(ascii_letters) - 1)]
                    password += character

            elif list_choice == "numbers":
                if numbers:
                    character = digits[randint(0, len(digits) - 1)]
                    password += character
            else:
                if special:
                    character = punctuation[randint(0, len(punctuation) - 1)]
                    password += character
        return password

    # Check input
    if not letters and not numbers and not special:
        print("Can't generate a password without any characters")
        raise Exception("Can't generate a password without any characters")

    # handles float inputs by rounding it to no decimal places
    password_length: int = round(password_length)

    # get min. password_length based on passed parameters
    if characters_occurring_at_least_once:
        min_password_length: int = 0
        if letters:
            min_password_length += 2 # is 2 because the password must contain at least one lowercase and one uppercase letter
        if numbers:
            min_password_length += 1
        if special:
            min_password_length += 1
    else:
        min_password_length: int = 1

    if password_length < min_password_length:
        raise Exception(f"Password length must be at least {min_password_length}")


    password = generate()
    if characters_occurring_at_least_once:
        while not is_character_occurring_at_least_once(password):
            print(f"I: Characters are not occurring at least once in generated Password. Generating a new password.\nPassword skipped: {password}")
            password = generate()

    return password


def main():
    #DEBUG
    for i in range(100):
        print(generate_password(password_length=5, letters=True, numbers=True, special=True, characters_occurring_at_least_once=True))

if __name__ == "__main__":
    main()
