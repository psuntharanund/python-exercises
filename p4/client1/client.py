""" 
Implement the 3DS Client. You may import additional modules as required from 
the python standard library or requirements.txt file provided on Github, as 
needed. 

When referencing files or directories, always use relative paths - do NOT hard 
code absolute paths.
"""

import requests
import base64
import json
import os
from cryptography.hazmat.primitives import hashes, serialization 
from cryptography.hazmat.primitives.asymmetric import padding, rsa

""" 
TODO: import additional modules as required from requirements.txt or the 
python standard library.
"""

logfile = "response.log"                # DO NOT MODIFY
server_name = "secure-shared-store"     # DO NOT MODIFY

""" 
These need to be created manually before you start coding. Use relative paths 
to reference the files. Do not hard code client names into the filenames. The 
names must be dynamically created based on which client is running.
"""
client_name = os.path.basename(os.path.dirname(os.path.abspath(__file__)))

node_certificate = os.path.join("certs", client_name + ".crt")

node_key = os.path.join("certs", client_name + ".key")

checked_out_doc = set()

def checkin_file_logout(session_token, doc_id, file_path):
    # uploads one document during logout with integrity protection. returns true when server confirms check in is successful 

    if (not doc_id or os.path.basename(doc_id) != doc_id or os.path.isabs(doc_id)):
        print(f"Unsafe document ID: {doc_id}")
        return False

    # don't follow symlink during logout, a malicious symlink could cause unintended local file to be uploaded
    try:
        if os.path.islink(file_path):
            print(f"Refusing to upload symbolic link: {doc_id}")
            return False

        if not os.path.isfile(file_path):
            print(f"Checkout file not found: {doc_id}")
            return False

        with open(file_path, "rb") as doc_file:
            doc_bytes = doc_file.read()

    except OSError as e:
        print(f"Unable to read {doc_id}: {e}")
        return False

    body = {
        "token": session_token,
        "document-id": doc_id,
        "security-flag": 2,
        "document": base64.b64encode(doc_bytes).decode("utf8")
    }

    try:
        server_response = post_request(server_name, "checkin", body, node_certificate, node_key)

    except requests.RequestException as e:
        print(f"Unable to check in {doc_id}: {e}")
        return False

    except ValueError:
        print(f"Server returned invalid response while checking in {doc_id}")
        return False

    if server_response.json().get("status") != 200:
        print(server_response.json().get("message", f"Unable to check in {doc_id}."))
        return False

    print(server_response.json().get("message", f"{doc_id} successfully checked in."))

    return True

""" <!!! DO NOT MODIFY THIS FUNCTION !!!>"""
def post_request(server_name, action, body, node_certificate, node_key):
    """
        * node_certificate is the name of the certificate file of the client 
        node (present inside certs).
        * node_key is the name of the private key of the client node (present 
        inside certs).
        * body parameter should in json format.
    """
    request_url = "https://{}/{}".format(server_name, action)
    request_headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(node_certificate, node_key),
        verify="../CA/CA.crt",
        timeout=(10, 20),
    )
    with open(logfile, "wb") as f:
        f.write(response.content)

    return response

""" 
You can begin modification from here
"""

def sign_statement(statement, user_private_key_file):
    # TODO: Implement sign statement functionality
    try:
        with open(user_private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password = None)
        
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("User private key is not an RSA private key.")

        signed_statement = private_key.sign(statement.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())


        return signed_statement

    except (OSError, ValueError, TypeError) as error:
        print(f"Unable to sign login statement: {error}")
        return None

def login():
    """
        # TODO: Accept the
         - user-id
         - name of private key file(should be present in the userkeys folder) of the user.
        Generate the login statement as given in writeup and its signature.
        Send request to server with required parameters (Ex: action = "login") using the
        post_request function given.
        The request body should contain the user-id, statement and signed statement.
    """

    successful_login = False

    while not successful_login:
        # get the user id from the user input or default to user1
        user_id = (input(" User Id: ") or "user1")


        # get the user private key filename or default to user1.key
        private_key_filename = (input(" Private Key Filename: ".strip() or user_id + ".key"))
        
        if os.path.basename(private_key_filename) != private_key_filename:
            print("Private key must be in userkeys folder.")
            continue

        # complete the relative path of the user private key filename (depends on the client)
        # Ex: "./userkeys/" + private_key_filename
        user_private_key_file = os.path.join("userkeys", private_key_filename)

        # check for if private key is not found, otherwise it will crash
        if not os.path.isfile(user_private_key_file):
            print("Private key file not found.")
            continue

        # create the statement
        statement = f"{client_name} as {user_id} logs into the Server"
        signed_statement = sign_statement(statement, user_private_key_file)

        if signed_statement is None:
            continue

        body = {
            "user-id": user_id,
            "statement": statement,
            "signed-statement": base64.b64encode(signed_statement).decode("utf8")
        }
       
        try:    
            server_response = post_request(
                server_name, 
                "login", 
                body, 
                node_certificate, 
                node_key
            )
        
        except requests.RequestException as error:
            print(f"Unable to connect to server: {error}")
            continue
        
        except ValueError:
            print("Server returned invalid response.")
            continue

        if server_response.json().get("status") == 200:
            successful_login = True
            print(server_response.json().get("message"))
            return server_response.json()
        
        print(server_response.json().get("message", "Login failed."))



def checkin(session_token):
    """
        # TODO: Accept the
         - DID: document id (filename)
         - security flag (1 for confidentiality  and 2 for integrity)
        Send the request to server with required parameters (action = "checkin") using post_request().
        The request body should contain the required parameters to ensure the file is sent to the server.
    """
    
    successful_login = False
    doc_id = input("Document ID/Filename: ").strip()
    client_dir = os.path.dirname(os.path.abspath(__file__))
    checkin_dir = os.path.join(client_dir, "documents", "checkin", doc_id)
     
    checkout_dir = os.path.join("documents","checkout",doc_id)

    while not successful_login:

        if not doc_id:
            print("Document ID cannot be empty.")
            return None
       
        # prevent other paths being written to where we want it
        if os.path.basename(doc_id) != doc_id:
            print("Document ID must only contain a file name.")
            return None
   
        # accept security flag
        print("Security flag: ")
        print("1) Confidentiality")
        print("2) Integrity")
        sec_flag = input()

        if sec_flag not in {"1", "2"}:
            print("Security flag not set correctly, please pick option 1 - Confidentiality or 2 - Integrity")
            return None
        
        # checked out doc needs to be moved back into checkin before upload
        if (doc_id in checked_out_doc and os.path.isfile(checkout_dir)):
            os.makedirs(os.path.dirname(checkin_dir), exist_ok = True)

            try:
                os.replace(checkout_dir, checkin_dir)
            
            except OSError as e:
                print(f"Unable to move document into check in folder: {e}")
                return None

        # validate that file exists
        if not os.path.isfile(checkin_dir):
            print(f"Document {doc_id} does not exist in {checkin_dir}")
            return None 
        
        # read document 
        try:
            with open(checkin_dir, "rb") as file:
                doc_bytes = file.read()
        except OSError as e:
            print(f"Error reading document: {e}")
            return None

        # encode for transport
        encoded_doc = base64.b64encode(doc_bytes).decode("utf-8")
        
        body = {
            "session-token": session_token,
            "document-id": doc_id,
            "security-flag": sec_flag,
            "document": encoded_doc 
        }


        try:    
            server_response = post_request(
                server_name, 
                "checkin", 
                body, 
                node_certificate, 
                node_key
            )
        
        except requests.RequestException as error:
            print(f"Unable to connect to server: {error}")
            continue
        
        except ValueError:
            print("Server returned invalid response.")
            continue

        if server_response.json().get("status") == 200:
            successful_login = True
            checked_out_doc.discard(doc_id)
            print(server_response.json().get("message"))
            return server_response.json()
        
        print(server_response.json().get(
            "message", 
            "Document check in failed."
            ))

def checkout(session_token):
    """
        # TODO:
        Send request to server with required parameters (action = "checkout") using post_request()

    """
    successful_login = False
    checkout_dir = os.path.join("documents", "checkout")
    doc_id = input("Document ID/Filename: ").strip()


    while not successful_login:
        if not doc_id:
            print("Document ID can't be empty.")
            return None

        # prevent other paths from being written into it 
        if os.path.basename(doc_id) != doc_id:
            print("Document ID must contain only a filename.")
            return None

        body = {
            "token": session_token,
            "document-id": doc_id 
        }
        
        try:
            server_response = post_request(
            server_name,
            "checkout",
            body,
            node_certificate,
            node_key
        )

        except requests.RequestException as error:
            print(f"Unable to connect to server: {error}")
            continue

        except ValueError:
            print("Server returned invalid response.")
            continue

        if server_response.json().get("status") == 200:
            successful_login = True
            print(server_response.json().get("message"))
            return server_response.json()

        print(server_response.json().get(
            "message",
            "Document check out failed."
        ))

        encoded_doc = server_response.json().get("file")

        if not encoded_doc:
            print("The server did not return a document.")
            return None 

        try:
            doc_bytes = base64.b64decode(
                encoded_doc,
                validate = True 
            )
    
        except (ValueError, TypeError):
            print("The server returned invalid document data.")
            return None

        os.makedirs(checkout_dir, exist_ok = True)

        checkout_path = os.path.join(checkout_dir,doc_id)

        try:
            with open(checkout_path, "wb") as doc_file:
                doc_file.write(doc_bytes)

        except OSError as e:
            print(f"Unable to save checked out document: {e}")
            return None

        checked_out_doc.add(doc_id)

        print(server_response.json().get("message", "Document Successfully checked out"))

def grant(session_token):
    """
        # TODO:
         - DID
         - target user to whom access should be granted (0 for all user)
         - type of access to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
         - time duration (in seconds) for which access is granted
        Send request to server with required parameters (action = "grant") using post_request()
    """
    
    doc_id = input("Document ID: ").strip()

    if not doc_id:
        print("Document ID can't be empty.")
        return None

    if os.path.basename(doc_id) != doc_id:
        print("Document ID must contain only a filename.")
        return None

    target_user = input("Target user ID (0 for all users): ").strip()

    if not target_user:
        print("Target user can't be empty.")
        return None

    # prevent values that could later be used as paths
    if target_user != "0":
        if os.path.basename(target_user) != target_user:
            print("Invalid target user.")
            return None

    print("Access: ")
    print("1) Check in")
    print("2) Check out")
    print("3) Both")

    access_right = input("Selection: ").strip()

    if access_right not in {"1", "2", "3"}:
        print("Access rights must be either 1, 2 or 3.")
        return None

    duration_input = input("Grant duration in seconds: ").strip()

    try:
        duration = int(duration_input)

        if duration <= 0:
            raise ValueError

    except ValueError:
        print("Duration must be a positive integer.")

    body = {
        "token": session_token,
        "document-id": doc_id,
        "target-user": target_user,
        "access-right": int(access_right),
        "duration": duration
    }

    try:
        server_response = post_request(server_name, "grant", body, node_certificate, node_key)

    except requests.RequestException as e:
        print(f"Unable to connect to server: {e}")
        return None

    except ValueError:
        print("Server returned an invalid response.")
        return None

    print(server_response.json().get("message", "Grant request failed."))

    return server_response.json()


def delete(session_token):
    """
        # TODO:
        Send request to server with required parameters (action = "delete")
        using post_request().
    """
    
    doc_id = input("Document ID: ").strip()

    if not doc_id:
        print("Document ID can't be empty.")
        return None

    # prevent values that could later be used as paths
    if (os.path.basename(doc_id) != doc_id or os.path.isabs(doc_id)):
        print("Document ID must contain only a filename.")

    confirmation = input(f"Delete '{doc_id}' permanently? (y/n)")

    if confirmation != "y" or confirmation != "Y":
            print("Delete cancelled.")

    body = {
        "token": session_token,
        "document-id": doc_id
    }

    try:
        server_response = post_request(server_name, "delete", body, node_certificate, node_key)

    except requests.RequestException as e:
        print(f"Unable to connect to server: {e}")
        return None

    except ValueError:
        print("Server returned an invalid response.")
        return None

    print(server_response.json().get("message", "Document deletion failed."))

    if server_response.json().get("status") == 200:
        checked_out_doc.discard(doc_id)

        checkout_path = os.path.join("documents", "checkout", doc_id)
        
        if os.path.isfile(checkout_path):
            try:
                os.remove(checkout_path)

            except OSError as e:
                print("Server copy was deleted, but local copy could not be removed: {e}")
    
    return server_response.json()


def logout(session_token):
    """
        # TODO: Ensure all the modified checked out documents are checked back in.
        Send request to server with required parameters (action = "logout") using post_request()
        The request body should contain the user-id, session-token
    """

    if not session_token:
        print("No active session.")
        return False

    checkout_dir = os.path.join("documents", "checkout")
    checkin_dir = os.path.join("documents", "checkin")

    os.makedirs(checkout_dir, exist_ok = True)
    os.makedirs(checkin_dir, exist_ok = True)

    try:
        checkout_entries = os.listdir(checkout_dir)

    except OSError as e:
        print(f"Unable to inspect checkout folder: {e}")
        return False

    checkout_files = []

    for doc_id in checkout_entries:
        checkout_path = os.path.join(checkout_dir, doc_id)

        # refuse symbolic links
        if os.path.islink(checkout_path):
            print(f"Logout stopped: symbolic link found at {doc_id}")
            return False

        if os.path.isfile(checkout_path):
            checkout_files.append(doc_id)

    # process files
    checkout_files.sort()

    for doc_id in checkout_files:
        checkout_path = os.path.join(checkout_dir, doc_id)
        checkin_path = os.path.join(checkin_dir, doc_id)

        if os.path.exists(checkin_path):
            print(f"Logout stopped: {doc_id} already exists in checkin folder.")
            return False
        
        try:
            #doing a replace here ensures that an unrelated checkin file is not silently overwritten 
            #since we are rejecting an existing destination in the above
            os.replace(checkout_path, checkin_path)
        
        except OSError as e:
            print(f"Unable to move {doc_id} into checkin folder: {e}")
            return False

        upload_success = checkin_file_logout(session_token, doc_id, checkin_path)

        if not upload_success:
            try:
                if (os.path.isfile(checkin_path) and not os.path.exists(checkout_path)):
                    os.replace(checkin_path, checkout_path)
            
            except OSError as rollback_e:
                print(f"Warning: unable to restore {doc_id} to checkout: {rollback_e}")

            print("Logout was not completed because one or more documents could not be checked in.")
            return False
        
        checked_out_doc.discard(doc_id)

    body = {
        "token": session_token 
    }
    
    try:
        server_response = post_request(server_name, "logout", body, node_certificate, node_key)

    except requests.RequestException as e:
        print(f"Unable to terminate server session: {e}")
        return False

    except ValueError:
        print("Server returned an invalid logout response.")
        return False

    if server_response.json().get("status") != 200:
        print(server_response.json().get("message", "Logout failed."))
        return False

    print(server_response.json().get("message", "Logout successful."))

    return True 

def print_main_menu():
    """
    print main menu
    :return: nothing
    """
    print(" Enter Option: ")
    print("    1. Checkin")
    print("    2. Checkout")
    print("    3. Grant")
    print("    4. Delete")
    print("    5. Logout")
    return


def main():
    """
        # TODO: Authenticate the user by calling login.
        If the login is successful, provide the following options to the user
            1. Checkin
            2. Checkout
            3. Grant
            4. Delete
            5. Logout
        The options will be the indices as shown above. For example, if user
        enters 1, it must invoke the Checkin function. Appropriate functions
        should be invoked depending on the user input. Users should be able to
        perform these actions in a loop until they logout. This mapping should
        be maintained in your implementation for the options.
    """

    # Initialize variables to keep track of progress
    server_message = "UNKNOWN"
    server_status = "UNKNOWN"
    session_token = "UNKNOWN"
    is_login = False

    # test()
    # return
    login_return = login()

    server_message = login_return["message"]
    server_status = login_return["status"]
    session_token = login_return["session_token"]

    print("\nThis is the server response")
    print(server_message)
    print(server_status)
    print(session_token)

    if server_status == 200:
        is_login = True

    while is_login:
        print_main_menu()
        user_choice = input()
        if user_choice == "1":
            checkin(session_token)
        elif user_choice == "2":
            checkout(session_token)
        elif user_choice == "3":
            grant(session_token)
        elif user_choice == "4":
            delete(session_token)
        elif user_choice == "5":
            logout(session_token)
        else:
            print("not a valid choice")


if __name__ == "__main__":
    main()
