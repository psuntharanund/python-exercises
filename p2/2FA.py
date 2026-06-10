from passlib.hash import sha512_crypt

SHADOW_FILE = "./app/shadow"
PASSWD_FILE = "./app/passwd"

def user_exists(username):
    with open(SHADOW_FILE, 'r') as file:
        for line in file:
            if line.startswith(username + ":"):
                return True 
    with open(PASSWD_FILE, 'r') as file:
        for line in file:
            if  line.startswith(username + ":"):
                return True
    return False

def authenticate(username, password, token):
    with open('./app/shadow', 'r') as file:
        for line in file:
            temp = line.split(':')
            if temp[0] == username:
                stored_hash = temp[1]
                hpassword = password + token 
                return sha512_crypt.verify(hpassword, stored_hash);
    return False

def update_shadow_file(username, hpassword):
    shadow_line = f"{username}:{hpassword}:19446:0:99999:7:::"
    with open(SHADOW_FILE, 'a+') as shadow_file:
        shadow_file.write(shadow_line + '\n')

def update_shadow_password(username, npassword, nsalt, nt):
    new_hash = sha512_crypt.hash(npassword + nt, salt = nsalt, rounds = 5000)

    lines = []
    
    with open(SHADOW_FILE, 'r') as file:
        for line in file:
            fields = line.split(':')
            fields[1] = new_hash
            line = ":".join(fields)
            
            lines.append(line)

    with open(SHADOW_FILE, "w") as file:
        for line in lines:
            file.write(line + "\n")

def update_passwd_file(username):
    count = 10

    with open(PASSWD_FILE, 'r') as f:
        for line in f:
            temp1 = line.split(':')
            while count <= int(temp1[3]) < 65534:
                count = int(temp1[3]) + 1 
        count = str(count)

    passwd_line = f"{username}:x:{count}:{count}:{username}:/home/{username}:/bin/bash"
    with open(PASSWD_FILE, 'a+') as passwd_file:
        passwd_file.write(passwd_line + '\n')

def create_user():
    username = input("Username: ")
    password = input("Password: ")
    rpassword = input("Confirm Password: ")
    salt = input("Salt: ")
    it = input("Initial Token: ")
    hpassword = sha512_crypt.hash(password + it, salt = salt, rounds = 5000)

    if password != rpassword:
        print("FAILURE: incorrect password")
        return 

    if user_exists(username):
        print(f"FAILURE: user {username} already exists")
        return
    else:
        update_passwd_file(username)
        update_shadow_file(username, hpassword)
        print(f"SUCCESS: {username} created")


def login():
    username = input("Username: ")
    password = input("Password: ")
    ct = input("Current Token: ")
    nt = input("Next Token: ")

    if not user_exists(username):
        print(f"FAILURE: user {username} does not exist")

    if authenticate(username, password, ct):
        print(f"SUCCESS: Login Successful")
    else:
        print(f"FAILURE:  either passwd or token incorrect")

def update_pw():
    username = input("Username: ")
    password = input("Password: ")
    npassword = input("New Password: ")
    rnpassword = input("Confirm New Password: ")
    nsalt = input("New Salt: ")
    ct = input("Current Token: ")
    nt = input("Next Token: ")

    if not user_exists(username):
        print(f"FAILURE: user {username} does not exist")

    if not authenticate(username, password, ct):
        print(f"FAILURE: either passwd or token incorrect")

    if npassword != rnpassword:
        print(f"New passwords do not match.")
        return
    
    update_shadow_password(username, npassword, nsalt, nt);
    print(f"SUCCESS: user {username} updated")

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
            elif choice == 2:
                login()
            elif choice == 3:
                update_pw()
            elif choice == 4:
                delete_user()
            else:
                print("Please choose a number between 1 and 4.")
        
        except ValueError:
            print("Please enter a valid number.")


