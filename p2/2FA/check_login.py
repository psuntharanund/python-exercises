import os
import sys
from passlib.hash import sha512_crypt


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def authenticate(self):
        """Authenticate the user."""
        with open('./app/shadow', 'r') as fp:
            for line in fp:
                temp = line.split(':')
                if temp[0] == self.username:
                    salt_and_pass = temp[1].split('$')
                    salt = salt_and_pass[2]
                    # Calculate hash using the retrieved salt and the password
                    calculated_hash = sha512_crypt.hash(self.password, salt_size=8, salt=salt, rounds=5000)
                    return calculated_hash == temp[1]
        return False

def get_user_credentials():
    """Get username and password from the user."""
    uname = input("Enter username: ")
    password = input(f"Enter Password for {uname}: ")
    return uname, password


def main():
    uname, password = get_user_credentials()

    user = User(uname, password)

    if user.authenticate():
        print("Login successful.")
    else:
        print("Invalid Password or User does not exist.")


if __name__ == '__main__':
    main()
