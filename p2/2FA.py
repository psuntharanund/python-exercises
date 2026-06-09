def create_user():
    username = input("Username: ")
    password = input("Password: ")
    rpassword = input("Confirm Password: ")
    salt = input("Salt: ")
    it = input("Initial Token: ")

def login():
    username = input("Username: ")
    password = input("Password: ")
    ct = input("Current Token: ")
    nt = input("Next Token ")

def update_pw():
    username = input("Username: ")
    password = input("Password: ")
    npassword = input("New Password: ")
    rnpassword = input("Confirm New Password: ")
    nsalt = input("New Salt: ")
    ct = input("Current Token: ")
    nt = input("Next Token: ")

def delete_user():
    username = input("Username: ")
    password = input("Password: ")
    ct = input("Current Token: ")

def main():
    while True:
        try:
            choice = int(input(
                "\nSelect an action:\n"
                    "1) Create a user\n"
                    "2) Login\n"
                    "3) Update password\n"
                    "4) Delete user account\n"
            ))

            if choice == 1:
                create_user()
            if choice == 2:
                login()
            if choice == 3:
                update_pw()
            if choice == 4:
                delete_user()
            else:
                print("Please choose a number between 1 and 4.")
        
        except ValueError:
            print("Please enter a valid number.")


