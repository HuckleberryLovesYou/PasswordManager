from random import choice, randint
from string import ascii_letters, digits, punctuation


# DO NOT USE IT TO STORE ANY IMPORTANT DATA
# THIS IS JUST A FUN PROJECT NOT MEANT TO BE USED

class PasswordGenerator:
    def __init__(self):
        self.password: str = ""
        self.password_length: int = 0
        self.generate_letters: bool = False
        self.generate_numbers: bool = False
        self.generate_special: bool = False

    def configure_generation(self, password_length: int, letters=True, numbers=True, special=True):
        self.generate_letters = letters
        self.generate_numbers = numbers
        self.generate_special = special
        self.password_length = password_length

        self.has_minimum_password_length()
        if not letters and not numbers and not special:
            raise Exception("Can't generate a password without any characters")

        if password_length > 10000:
            print("Generating a password longer than 10000 could take some time.")



    def has_minimum_password_length(self) -> bool:
        min_password_length: int = 0
        if self.generate_letters:
            min_password_length += 2  # its 2 because of upper-  and lowercase characters
        if self.generate_numbers:
            min_password_length += 1
        if self.generate_special:
            min_password_length += 1

        if self.password_length < min_password_length:
            raise Exception(f"The password length({self.password_length}) specified is less than the minimum length ({min_password_length})\nThe minimum length changes depending on parameters passed to self.configure_generation")
        else:
            return True


    def generate(self) -> str:
        while True:
            self.password = ""
            for _ in range(self.password_length):
                match choice(["letters", "numbers", "special"]):
                    case "letters":
                        self.password += choice(ascii_letters)
                    case "numbers":
                        self.password += choice(digits)
                    case "special":
                        self.password += choice(punctuation)
                    
            if self.has_required_characters():
                return self.password

    def has_required_characters(self) -> bool:
        has_lowercase: bool = False
        has_uppercase: bool = False
        has_number: bool = False
        has_special: bool = False

        # Checks password for characters
        for character in self.password:
            if self.generate_letters:
                if character in ascii_letters:
                    if character.islower():
                        has_lowercase = True
                    else:
                        has_uppercase = True
            else:
                has_lowercase = True
                has_uppercase = True

            if self.generate_numbers:
                if character in digits:
                    has_number = True
            else:
                has_number = True

            if self.generate_special:
                if character in punctuation:
                    has_special = True
            else:
                has_special = True

        # Evaluation
        if has_lowercase and has_uppercase and has_number and has_special:
            return True
        else:
            return False


def main():
    #DEBUG
    for _ in range(1):
        generator = PasswordGenerator()
        generator.configure_generation(10, letters=True, numbers=True, special=True)
        print(generator.generate())




if __name__ == "__main__":
    main()
