from passlib.hash import sha512_crypt
import subprocess
import time
import sys
import os

# Can change if you want.  Don't really need to.
# TODO: Change this to a file with 'a' if you want to log the outputs.
# FNULL = open(os.devnull, "w")
FNULL = open("debug.log", "a")

SHADOW_FILE = './2FA/app/shadow'
PASSWORD_FILE = './2FA/app/passwd'

GRADE = {
    "TC2": 8,   # Create User 1 it should succeed
    "TC3": 8,   # Create User 2 it should succeed
    "TC4": 6,     # Create duplicate user, it should fail.
    "TC5": 16,    # Login with user 1 with correct credentials, it should succeed
    "TC6": 6,     # Login with user 2 with incorrect credentials, it should fail
    "TC7": 13,    # Update user 2 with correct credentials, it should succeed
    "TC8": 6,     # Update user 1 with incorrect credentials, it should fail
    "TC9": 12,   # Delete User 1
    "TC10": 5,  # Delete User 2 with incorrect credentials
}
PERFECT_GRADE = {
    "TC2": 8,   # Create User 1 it should succeed
    "TC3": 8,   # Create User 2 it should succeed
    "TC4": 6,     # Create duplicate user, it should fail.
    "TC5": 16,    # Login with user 1 with correct credentials, it should succeed
    "TC6": 6,     # Login with user 2 with incorrect credentials, it should fail
    "TC7": 13,    # Update user 2 with correct credentials, it should succeed
    "TC8": 6,     # Update user 1 with incorrect credentials, it should fail
    "TC9": 12,   # Delete User 1, it should succeed
    "TC10": 5,  # Delete User 2 with incorrect credentials, it should failed
}
TASK_COMMENT = {
    "TC2": 'User 1 created successfully',   # Create User 1
    "TC3": 'User 2 created successfully',   # Create User 2
    "TC4": 'Did not create duplicate user (success)',   # Create duplicate user, it should fail.
    "TC5": 'Logged successfully with user 1',   # Login with user 1 with correct credentials, it should succeed
    "TC6": 'Failed to log with user 2 (success)',   # Login with user 2 with incorrect credentials, it should fail
    "TC7": 'Updated User 2 Successfully',   # Update user 2 with correct credentials, it should succeed
    "TC8": 'Failed to update user 1 (success)',   # Update with user 1 with incorrect credentials, it should fail
    "TC9": 'Deleted user 1',   # Delete User 1, it should succeed
    "TC10": 'Deleted user 2',  # Delete User 2 with incorrect credentials, it should failed
}

def main():
    # TODO: Change the name of you 2FA python code (if needed)
    file = "2FA.py"  # This is your code
    print("The 2FA Python File file name is:\t", file)

    #########################################
    ## Start of variables used in the autograder code
    user1_username = "user1"
    user1_password1 = "password1"
    user1_password2 = "password2"
    user1_salt1 = "cs623811"
    user1_salt2 = "cs623812"
    user1_token1 = "3SRxSTFOL9lMo9Sawdini0"
    user1_token2 = "qQkfaAOqsAjDOeCqUBbEb/"

    user2_username = "user2"
    user2_password1 = "password1"
    user2_password2 = "password2"
    user2_salt1 = "cs623821"
    user2_salt2 = "cs623822"
    user2_token1 = "TH8XaK75tBOh/tAp8gqeB."
    user2_token2 = "QA8n9gHZmu/W/mKi9xTpl1"

    ####################################################################################
    ## In this section we start with the autograder code
    ####################################################################################
    # Create New User Test for User 1 (TC2) - Success expected
    print("Create New User Test - User 1")
    client = start_client(file)
    create_new_user(client, user1_username, user1_password1, user1_salt1, user1_token1)
    time.sleep(1)
    result = check_create_new_user_result(user1_username, user1_password1 + user1_token1)
    if result:
        print(f'\033[32mCreation of user {user1_username} successful\033[0m')
        GRADE['TC2'] = 8
    else:
        print("Invalid Password or User Does Not Exist")
        GRADE['TC2'] = 0
        TASK_COMMENT['TC2'] = 'Failed to create user 1'
    ####################################################################################
    # Create New User Test for User 2 (TC3) - Success expected
    print("Create New User Test - User 2")
    client = start_client(file)
    create_new_user(client, user2_username, user2_password1, user2_salt1, user2_token1)
    time.sleep(1)
    result = check_create_new_user_result(user2_username, user2_password1 + user2_token1)
    if result:
        print(f'\033[32mCreation of user {user2_username} successful\033[0m')
        GRADE['TC3'] = 8
    else:
        print("Invalid Password or User Does Not Exist")
        GRADE['TC3'] = 0
        TASK_COMMENT['TC3'] = 'Failed to create user 2'
    ####################################################################################
    # Create Duplicate User Test for User 2 (TC4) - Failure expected
    print("Create Duplicate User Tests - User 2")
    client = start_client(file)
    create_new_user(client, user2_username, user2_password1, user2_salt1, user2_token1)
    time.sleep(1)
    result = user_exists_duplicated_passwd_file(user2_username)
    if result:
        print(f'User {user2_username} found duplicated in the password file')
        GRADE['TC4'] = 0
        TASK_COMMENT['TC3'] = 'Failed test to create a duplicate user'
    else:
        print(f'\033[32mUser {user2_username} not duplicated in password file.\033[0m')
        GRADE['TC4'] = 6
    ####################################################################################
    # Log with User 1 (TC5) - Success Expected (valid credentials)
    print("Login Test - User 1")
    client = start_client(file)
    login_with_user(client, user1_username, user1_password1, user1_token1, user1_token2)
    time.sleep(1)
    result = check_create_new_user_result(user1_username, user1_password1 + user1_token2)
    if result:
        print(f'\033[32mUser {user1_username} logged successfully.\033[0m')
        GRADE['TC5'] = 16
    else:
        print(f'User {user1_username} failed login.')
        GRADE['TC5'] = 0
        TASK_COMMENT['TC5'] = 'Failed to login with user 1'
####################################################################################
    # Log with User 2 (TC6) - Failure Expected (invalid credentials)
    print("Login Tests - User 2")
    client = start_client(file)
    login_with_user(client, user2_username, "wrong-password", user2_token1, user2_token2)
    time.sleep(1)
    result = check_create_new_user_result(user2_username, user2_password1 + user2_token2)
    if result:
        print(f'User {user2_username} logged successfully.')
        GRADE['TC6'] = 0
        TASK_COMMENT['TC6'] = 'Failed to fail to login user 2 using the wrong credentials'
    else:
        print(f'\033[32mUser {user2_username} failed login.\033[0m')
        GRADE['TC6'] = 6
####################################################################################
    # Update User 2 (TC7) - Success expected (valid credentials)
    print(f'Update User 2 test with valid credentials')
    client = start_client(file)
    update_user(client, user2_username, user2_password1, user2_password2, user2_salt2, user2_token1, user2_token2)
    time.sleep(3)
    result = check_create_new_user_result(user2_username, user2_password2 + user2_token2)
    if result:
        print(f'\033[32mUser {user2_username} updated successfully.\033[0m')
        GRADE['TC7'] = 13
    else:
        GRADE['TC7'] = 0
        print(f'\033[31mUser {user2_username} failed to update.\033[0m')
        TASK_COMMENT['TC7'] = 'Failed to update user 2'
####################################################################################
    # Update User 1 (TC8) - Failure expected (invalid credentials)
    print(f'Update User 1 test with invalid credentials')
    client = start_client(file)
    update_user(client, user1_username, "wrong-password", user1_password2, user1_salt2, user1_token1, user1_token2)
    time.sleep(3)
    result = check_create_new_user_result(user1_username, user1_password2 + user1_token2)
    if result:
        print(f'\033[31mUser {user1_username} updated successfully.\033[0m')
        GRADE['TC8'] = 0
        TASK_COMMENT['TC8'] = 'Failed to fail updating user 1'
    else:
        print(f'\033[32mUser {user1_username} failed to update.\033[0m')
        GRADE['TC8'] = 6
####################################################################################
    # Delete User 1 (TC9)  - Success expected
    print("Delete User Test - User 1")
    client = start_client(file)
    delete_user(client, user1_username, user1_password1, user1_token2)
    time.sleep(2)
    if user_exists_passwd_file(user1_username) or user_exists_shadow_file(user1_username):
        print(f'\033[31mUser {user1_username} exists in passwd or shadow file.\033[0m')
        GRADE['TC9'] = 0
        TASK_COMMENT['TC9'] = 'Failed to delete user 1'
    else:
        print(f'\033[32mUser {user1_username} deleted successfully.\033[0m')
        GRADE['TC9'] = 12
####################################################################################
    # Delete User 2 (TC10)  - Fail expected
    print("Delete User Test - User 2")
    client = start_client(file)
    delete_user(client, user2_username, "wrong-password", user2_token2)
    time.sleep(2)
    if not (user_exists_passwd_file(user2_username) or user_exists_shadow_file(user2_username)):
        print(f'\033[31mUser {user2_username} deleted successfully with incorrect credentials.\033[0m')
        GRADE['TC10'] = 0
        TASK_COMMENT['TC10'] = 'Succeeded to delete user 2'
    else:
        print(f'\033[32mUser {user2_username} delete failed.\033[0m')
        GRADE['TC10'] = 5
####################################################################################

####################################################################################

    imprime_grade() # print GRADE

def start_client(client_name):
    client = subprocess.Popen(
        ["python3", client_name],
        cwd=os.getcwd(),
        stdin=subprocess.PIPE,
        stdout=FNULL,
        stderr=FNULL,
        bufsize=1,
        universal_newlines=True
    )
    return client

def create_new_user(proc, username, passwd, salt, initial_token):
    try:
        proc.stdin.write("1" + "\n")
        proc.stdin.write(username + "\n")
        proc.stdin.write(passwd + "\n")
        proc.stdin.write(passwd + "\n")
        proc.stdin.write(salt + "\n")
        proc.stdin.write(initial_token + "\n")
    except:
        pass

def update_user(proc, username, passwd, new_passwd, new_salt, current_token, next_token):
    try:
        proc.stdin.write("3" + "\n")
        proc.stdin.write(username + "\n")
        proc.stdin.write(passwd + "\n")
        proc.stdin.write(new_passwd + "\n")
        proc.stdin.write(new_passwd + "\n")
        proc.stdin.write(new_salt + "\n")
        proc.stdin.write(current_token + "\n")
        proc.stdin.write(next_token + "\n")
    except:
        pass

def login_with_user(proc, username, passwd, current_token, next_token):
    try:
        proc.stdin.write("2" + "\n")
        proc.stdin.write(username + "\n")
        proc.stdin.write(passwd + "\n")
        proc.stdin.write(current_token + "\n")
        proc.stdin.write(next_token + "\n")
    except:
        pass

def delete_user(proc, username, passwd, current_token):
    try:
        proc.stdin.write("4" + "\n")
        proc.stdin.write(username + "\n")
        proc.stdin.write(passwd + "\n")
        proc.stdin.write(current_token + "\n")
    except:
        pass

def check_create_new_user_result(uname, passwd):
    with open(SHADOW_FILE, 'r') as fp:
        # Enumerating through all the entries in shadow file
        for line in fp:  # Enumerating through all the entries in shadow file
            temp = line.split(':')
            # Checking whether entered username exist or not
            if temp[0] == uname:  # Checking whether entered username exist or not
                # print(f'\nThe line with that username is {temp}')
                # retrieving salt and password against the user
                salt_and_pass = (temp[1])
                # print(f'The Salt and Password are: {salt_and_pass}')
                salt = salt_and_pass.split('$')[2]
                # print(f'This is the salt: {salt}')
                # calculating hash via salt from the shadow file and password entered by user
                result = sha512_crypt.hash(passwd, salt_size=8, salt=salt, rounds=5000)
                # print(f'This is the hash: {result}\n')
                # comparing generated salt with existing salt entry
                if result == temp[1]:
                    return True
                else:
                    return False

    # User does not exist
    return False

def imprime_grade():
    """
    GRADE = {
    "TC2": 8,   # Create User 1 it should succeed
    "TC3": 8,   # Create User 2 it should succeed
    "TC4": 6,     # Create duplicate user, it should fail.
    "TC5": 16,    # Login with user 1 with correct credentials, it should succeed
    "TC6": 6,     # Login with user 2 with incorrect credentials, it should fail
    "TC7": 13,    # Update user 2 with correct credentials, it should succeed
    "TC8": 6,     # Update user 1 with incorrect credentials, it should fail
    "TC9": 12,   # Delete User 1 with correct credentials, it should succeed
    "TC10": 5,  # Delete User 2 with incorrect credentials, it should fail
    }
    :return: N/A
    """
    if GRADE["TC2"] == 8:
        print(f'\033[32mTC2: {GRADE["TC2"]}\033[0m')
    else:
        print(f'\033[31mTC2: {GRADE["TC2"]}\033[0m')
    if GRADE["TC3"] == 8:
        print(f'\033[32mTC3: {GRADE["TC3"]}\033[0m')
    else:
        print(f'\033[31mTC3: {GRADE["TC3"]}\033[0m')
    if GRADE["TC4"] == 6:
        print(f'\033[32mTC4: {GRADE["TC4"]}\033[0m')
    else:
        print(f'\033[31mTC4: {GRADE["TC4"]}\033[0m')
    if GRADE["TC5"] == 16:
        print(f'\033[32mTC5: {GRADE["TC5"]}\033[0m')
    else:
        print(f'\033[31mTC5: {GRADE["TC5"]}\033[0m')
    if GRADE["TC6"] == 6:
        print(f'\033[32mTC6: {GRADE["TC6"]}\033[0m')
    else:
        print(f'\033[31mTC6: {GRADE["TC6"]}\033[0m')
    if GRADE["TC7"] == 13:
        print(f'\033[32mTC7: {GRADE["TC7"]}\033[0m')
    else:
        print(f'\033[31mTC7: {GRADE["TC7"]}\033[0m')
    if GRADE["TC8"] == 6:
        print(f'\033[32mTC8: {GRADE["TC8"]}\033[0m')
    else:
        print(f'\033[31mTC8: {GRADE["TC8"]}\033[0m')
    if GRADE["TC9"] == 12:
        print(f'\033[32mTC9: {GRADE["TC9"]}\033[0m')
    else:
        print(f'\033[31mTC9: {GRADE["TC9"]}\033[0m')
    if GRADE["TC10"] == 5:
        print(f'\033[32mTC10: {GRADE["TC10"]}\033[0m')
    else:
        print(f'\033[31mTC10: {GRADE["TC10"]}\033[0m')

    print(f'\n {TASK_COMMENT}')

def user_exists_passwd_file(username):
    # Return True if user 'username' exists in the /etc/passwd file
    user_exists_in_passwd = False
    with open(PASSWORD_FILE, 'r') as passwd_file:
        passwd_lines = passwd_file.readlines()
    passwd_file.close()
    for line_entry in passwd_lines:
        if line_entry.split(':')[0] == username:
            user_exists_in_passwd = True
    return user_exists_in_passwd

def user_exists_duplicated_passwd_file(username):
    count = 0
    # Return True if user 'username' exists duplicated in the /etc/passwd file
    user_duplicated_in_passwd = False
    with open(PASSWORD_FILE, 'r') as passwd_file:
        passwd_lines = passwd_file.readlines()
    for line_entry in passwd_lines:
        if line_entry.split(':')[0] == username:
            count = count + 1
    if count > 1:
        user_duplicated_in_passwd = True
    return user_duplicated_in_passwd

def user_exists_shadow_file(username):
    # Return True if user 'username' exists in the /etc/shadow file
    user_exists_in_shadow = False
    with open(SHADOW_FILE, 'r') as shadow_file:
        shadow_lines = shadow_file.readlines()
    shadow_file.close()
    for line_entry in shadow_lines:
        if line_entry.split(':')[0] == username:
            user_exists_in_shadow = True
    return user_exists_in_shadow

if __name__ == '__main__':
    main()
