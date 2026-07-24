''' 
Implement the 3DS Server. You may import additional modules as required from 
the the Python standard libraries or requirements.txt file provided on Github, 
as needed. 

When referencing files or directories, always use relative paths - do NOT hard 
code absolute paths.
'''

from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

''' 
TODO: import additional modules as required from requirements.txt or the 
python standard library.
'''
import base64
import json
import os
import secrets
import time


secure_shared_service = Flask(__name__)     # DO NOT MODIFY
api = Api(secure_shared_service)            # DO NOT MODIFY

active_sessions = {}
user_sessions = {}

server_private_key_file = os.path.join(
    "..",
    "certs",
    "secure-shared-store.key"
)

def load_server_private_key():
    with open(server_private_key_file, "rb") as private_key_file:
        return serialization.load_pem_private_key(private_key_file.read(), password = None)

server_public_key_file = os.path.join(
    "..",
    "certs",
    "secure-shared-store.pub"
)

def load_server_public_key():
    with open(server_public_key_file, "rb") as public_key_file:
        return serialization.load_pem_public_key(public_key_file.read())

def protect_confidential_document(doc_bytes):
    # this will help encrypt document using AESGCM key using the server RSA public key
    
    public_key = load_server_public_key()

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    aes_gcm = AESGCM(aes_key)
    
    encrypted_doc = aes_gcm.encrypt(nonce, doc_bytes, None)

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("User public key is not an RSA public key.")

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )

    return (
        encrypted_doc,
        encrypted_aes_key,
        nonce
    )

def protect_integrity_document(doc_bytes):
    # this signs document using server RSA private key
    
    private_key = load_server_private_key()

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("User private key is not an RSA private key.")

    signature = private_key.sign(doc_bytes, padding.PKCS1v15(), hashes.SHA256())

    return signature

def verify_integrity_document(doc_bytes, signature):
    # if option 2 is selected for security flag, this helps check the document
    public_key = load_server_public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("User public key is not an RSA public key.")

    try:
        public_key.verify(signature,doc_bytes,padding.PKCS1v15(),hashes.SHA256())
        
        return True

    except InvalidSignature:
        return False

def save_binary_file(filename, data):
    doc_dir = "documents"

    os.makedirs(doc_dir, exist_ok=True)

    file_path = os.path.join(doc_dir, filename)

    with open(file_path, "wb") as output_file:
        output_file.write(data)

def save_metadata(doc_id, sec_flag, owner):
    metadata = {
        "document-id": doc_id,
        "security-flag": sec_flag,
        "owner": owner
    }

    metadata_path = os.path.join("documents", doc_id + ".meta")

    with open(metadata_path, "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=4)

def user_verify_checkout(metadata, user_id):
    # this should permit checkout when user owns document or has active checkout role
    
    if metadata.get("owner") ==  user_id:
        return True

    grants = metadata.get("grants", [])

    for grant in grants:
        target_user = grant.get("user")
        access_type = grant.get("access")

        correct_user = (
            target_user == user_id
            or target_user == "0"
            or target_user == 0
        )

        checkout_allow = access_type in [2, 3, "2", "3"]

        if correct_user and checkout_allow:
            return True

    return False

def decrypt_confidential_document(encrypted_doc, encrypted_aes_key, nonce):
    # when security flag is 1, this will decrypt the document when it's requested
    private_key = load_server_private_key()

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("User private key is not an RSA private key.")

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf = padding.MGF1(
                algorithm = hashes.SHA256()
            ),
            algorithm = hashes.SHA256(),
            label = None
        ))
    
    aes_gcm = AESGCM(aes_key)

    doc_bytes = aes_gcm.decrypt(nonce,encrypted_doc,None)

    return doc_bytes

def user_has_access(metadata, user_id, requested_access):
    # verify user has access

    if metadata.get("owner") == user_id:
        return True

    grant_rule = metadata.get("grant")

    if not isinstance(grant_rule, dict):
        return False

    try:
        target_user = str(grant_rule.get("target-user"))
        expiration_time = float(grant_rule.get("expires-at"))
        access_right = int(grant_rule.get("access-right"))

    except (TypeError, ValueError):
        return False 

    if time.time() >= expiration_time:
        return False
    
    if target_user not in {"0", str(user_id)}:
        return False

    if requested_access == 1:
        return access_right in {1,3}

    if requested_access == 2:
        return access_right in {2,3}

    return False

def remove_present_file(file_path):
    # delete file if it exists
    
    if not os.path.exists(file_path):
        return True

    try:
        os.remove(file_path)
        return True

    except OSError as e:
        print(f"Unable to delete {file_path}: {e}")
        return False
    
def destroy_key(key_path):
    # when overwriting the file, we need to get rid of the old key to put the new one int
    
    if not os.path.isfile(key_path):
        return True

    try:
        key_size = os.path.getsize(key_path)

        with open(key_path, "r+b") as key_file:
                key_file.write(os.urandom(key_size))
                key_file.flush()
                os.fsync(key_file.fileno())

        os.remove(key_path)
        return True

    except OSError as e:
        print(f"Unable to destroy encryption key: {e}")
        return False

class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"

def verify_statement(statement, signed_statement, user_public_key_file):
    # TODO: Implement verify statement functionality

    try:
        with open(user_public_key_file, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())


        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("User public key is not an RSA public key.")

        public_key.verify(signed_statement, statement.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())

        return True
    
    except InvalidSignature:
        return False

    except (OSError, ValueError, TypeError):
        return False

class login(Resource):
    def post(self):
        data = request.get_json(silent = True)
        
        if not data:
            return jsonify({
                "status": 700,
                "message": "Login failed.",
                "session_token": "INVALID"
            })

        # TODO: Implement login functionality
        '''
            # TODO: Verify the signed statement.
            Response format for success and failure are given below. The same
            keys ('status', 'message', 'session_token') should be used.
            Expected response status codes:
            1) 200 - Login Successful
            2) 700 - Login Failed
        '''
        # Information coming from the client
        user_id = data.get("user-id")
        statement = data.get("statement")
        encoded_statement = data.get('signed-statement')
        
        if not user_id or not statement or not encoded_statement:
            return jsonify({
                "status": 700,
                "message": "Login Failed",
                "session_token": "INVALID"
            })

        # complete the relative path of the user public key filename
        if os.path.basename(user_id) != user_id:
            return jsonify({
                "status": 700,
                "message": "Login Failed",
                "session_token": "INVALID"
            })

        expected_statement_end = (f" as {user_id} logs into the Server")

        if not statement.endswith(expected_statement_end):
            return jsonify({
                "status": 700,
                "message": "Login Failed",
                "session_token": "INVALID"
            })


        # ./userpublickeys/{user_public_key_filename}
        user_public_key_file = os.path.join("userpublickeys", user_id + ".pub")
        
        if not os.path.isfile(user_public_key_file):
            return jsonify({
                "status": 700,
                "message": "Login Failed",
                "session_token": "INVALID"
            })

        try:
            signed_statement = base64.b64decode(encoded_statement, validate=True)

        except (ValueError, TypeError):
            return jsonify({
                "status": 700,
                "message": "Login Failed",
                "session_token": "INVALID"
            })

        success = verify_statement(
            statement, 
            signed_statement, 
            user_public_key_file
        )
        
        if not success:
            # Similar response format given below can be used for all the other functions
            return jsonify({
                'status': 700,
                'message': 'Login Failed',
                'session_token': "INVALID",
            })

        # invalidate user's previous session 
        old_token = user_sessions.get(user_id)

        if old_token:
            active_sessions.pop(old_token, None)
        
        session_token = secrets.token_urlsafe(32)
        active_sessions[session_token] = user_id
        user_sessions[user_id] = session_token

        return jsonify({
            "status": 200,
            "message": "Login Successful",
            "session_token": session_token
        })


class checkin(Resource):
    # TODO: Implement checkin functionality
    """
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    3) 700 - Other failures
    """

    def post(self):
        data = request.get_json(silent = True)
        
        if not data:
            return jsonify({
                "status": 700,
                "message": "Document check in failed."
            })

        token = data.get("token")
        doc_id = data.get("document-id")
        sec_flag = data.get("security-flag")
        encoded_doc = data.get("document")

        # validate session 
        user_id = active_sessions.get(token)

        if not user_id:
            return jsonify({
                "status": 702,
                "message": "Access denied checking in."
            })

        if (
            not doc_id 
            or encoded_doc is None 
            or sec_flag not in {1,2}
        ):
            return jsonify({
                "status": 700,
                "message": "Document check in failed."
            })

        # prevent different paths
        if (os.path.basename(doc_id) != doc_id or os.path.isabs(doc_id)):
            return jsonify({
                "status": 700,
                "message": "Invalid document ID."
            })
        
        doc_path = os.path.join("documents", doc_id)

        metadata_path = doc_path + ".meta"

        existing_metadata = None

        if os.path.isfile(metadata_path):
            try:
                with open(metadata_path, "r", encoding = "utf-8") as metadata_file:
                    existing_metadata = json.load(metadata_file)

            except (OSError, ValueError):
                return jsonify({
                    "status": 700,
                    "message": "Document check in failed."
                })

            if not user_has_access(existing_metadata, user_id, 1):
                return jsonify({
                    "status": 702,
                    "message": "Access denied checking in."
                })
        
        try:
            doc_bytes = base64.b64decode(
                encoded_doc,
                validate=True 
            )

            os.makedirs("documents", exist_ok = True)

            if sec_flag == 1:
                (encrypted_doc, encrypted_aes_key, nonce) = protect_confidential_document(doc_bytes)

                save_binary_file(doc_id + ".key", encrypted_aes_key )
                save_binary_file(doc_id, encrypted_doc)
                save_binary_file(doc_id + ".nonce", nonce)
                
                # remove old signature if flag is 2
                signature_path = doc_path + ".sig"

                if os.path.isfile(signature_path):
                    os.remove(signature_path)

            else:
                signature = protect_integrity_document(doc_bytes)

                save_binary_file(doc_id, doc_bytes)

                save_binary_file(doc_id + ".sig", signature)

                encrypted_key_path = doc_path + ".key"
                nonce_path = doc_path + ".nonce"

                if os.path.isfile(encrypted_key_path):
                    os.remove(encrypted_key_path)

                if os.path.isfile(nonce_path):
                    os.remove(nonce_path)

            owner = user_id
            existing_grant = None

            if existing_metadata is not None:
                owner = existing_metadata.get("owner", user_id)

                stored_grant = existing_metadata.get("grant")

                if isinstance(stored_grant, dict):
                    existing_grant = stored_grant

            metadata = {
                "document-id": doc_id,
                "security-flag": sec_flag,
                "owner": owner 
            }

            if existing_grant is not None:
                metadata["grant"] = existing_grant

            with open(metadata_path, "w", encoding = "utf-8") as metadata_file:
                json.dump(metadata, metadata_file, indent = 4)


        except (OSError, ValueError, TypeError) as e:
            print(f"Check in error: {e}")

            return jsonify({
                "status": 700,
                "message": "Document check in failed."
            })

        return jsonify({
            "status": 200,
            "message": "Document Successfully checked in"
        })


class checkout(Resource):
    # TODO: Implement checkout functionality
    """
    Expected response status codes
    1) 200 - Document Successfully checked out
    2) 702 - Access denied checking out
    3) 703 - Check out failed due to broken integrity
    4) 704 - Check out failed since file not found on the server
    5) 700 - Other failures
    """
    def post(self):
        data = request.get_json(silent = True)
        
        if not data:
            return jsonify({
                "status": 700,
                "message": "Document checkout failed.",
                "file": "Invalid"
            })

        token = data.get("token")
        doc_id = data.get("document-id")
        
        user_id = active_sessions.get(token)

        if not user_id:
            return jsonify({
                "status": 702,
                "message": "Access denied checking out.",
                "file": "Invalid"
            })

        if not doc_id:
            return jsonify({
                "status": 700,
                "message": "Document checkout failed.",
                "file": "Invalid"
            })
        
        if (os.path.basename(doc_id) != doc_id or os.path.isabs(doc_id)):
            return jsonify({
                "status": 700,
                "message": "Invalid document ID.",
                "file": "Invalid"
            })

        doc_path = os.path.join("documents", doc_id)

        metadata_path = doc_path + ".meta"

        if not os.path.isfile(doc_path):
            return jsonify({
                "status": 704,
                "message": "Check out failed due to file not found.",
                "file": "Invalid"
            }) 

        if not os.path.isfile(metadata_path):
            return jsonify({
                "status": 704,
                "message": "Check out failed due to metadata not being found.",
                "file": "Invalid"
            })

        # read metadata file
        try:
            with open(metadata_path, "r", encoding = "utf-8") as metadata_file:
                metadata = json.load(metadata_file)

        except (OSError, ValueError, TypeError):
            return jsonify({
                "status": 700,
                "message": "Document checkout failed.",
                "file": "Invalid"
            })

        if not user_has_access(metadata, user_id, 2):
            return jsonify({
                "status": 702,
                "message": "Access denied checking out.",
                "file": "Invalid"
            })

        sec_flag = metadata.get("security-flag")

        try:
            with open(doc_path, "rb") as doc_file:
                stored_doc = doc_file.read()

            if sec_flag in [1, "1"]:
                encrypted_key_path = doc_path + ".key"
                nonce_path = doc_path + ".nonce"

                if (not os.path.isfile(encrypted_key_path)
                    or not os.path.isfile(nonce_path)):
                    return jsonify({
                        "status": 704,
                        "message": "Check out failed due to file not being found on server.",
                        "file": "Invalid"
                    })
    
                with open(encrypted_key_path, "rb") as key_file:
                    encrypted_aes_key = key_file.read()

                with open(nonce_path, "rb") as nonce_file:
                    nonce = nonce_file.read()

                doc_bytes = decrypt_confidential_document(stored_doc, encrypted_aes_key, nonce)

            elif sec_flag in [2, "2"]:
                signature_path = doc_path + ".sig"

                if not os.path.isfile(signature_path):
                    return jsonify({
                        "status": 704,
                        "message": "Check out failed due to file not being found on server.",
                        "file": "Invalid"
                })

                with open(signature_path, "rb") as signature_file:
                    signature = signature_file.read()

                valid_integrity = verify_integrity_document(stored_doc, signature)

                if not valid_integrity:
                    return jsonify({
                        "status": 703,
                        "message": "Check out failed due to broken integrity.",
                        "file": "Invalid"
                })
                
                doc_bytes = stored_doc

            else:
                return jsonify({
                    "status": 700,
                    "message": "Invalid document security flag.",
                    "file": "Invalid"
            })

        except (OSError, ValueError, TypeError) as e:
            print(f"Checkout error: {e}")

            return jsonify({
                "status": 700,
                "message": "Document checkout failed.",
                "file": "Invalid"
            })

        encoded_doc = base64.b64encode(doc_bytes).decode("utf-8")

        return jsonify({
            "status": 200,
            "message": "Document Successfully checked out.",
            "file": encoded_doc
        })

class grant(Resource):
    # TODO: Implement grant functionality
    """
        Expected response status codes:
        1) 200 - Successfully granted access
        2) 702 - Access denied to grant access
        3) 700 - Other failures
    """
    def post(self):
        data = request.get_json(silent = True)
        
        if not data:
            return jsonify({
                "status": 700,
                "message": "Grant request failed."
            })

        token = data.get("token")
        doc_id = data.get("document-id")
        target_user = data.get("target-user")
        access_right = data.get("access-right")
        duration = data.get("duration")
        access_right = int(access_right)
        # confirm valid session
        user_request = active_sessions.get(token)

        if not user_request:
            return jsonify({
                "status": 702,
                "message": "Access denied to grant access."
            })

        if(not doc_id or target_user is None or access_right not in {1, 2, 3}):
            return jsonify({
                "status": 700,
                "message": "Grant request failed."
            })

        # prevent other paths writing into path
        if (os.path.basename(doc_id) != doc_id or os.path.isabs(doc_id)):
            return jsonify({
                "status": 700,
                "message": "Invalid document ID."
            })

        target_user = str(target_user)

        if target_user != "0":
            if (os.path.basename(target_user) != target_user or os.path.isabs(target_user)):
                return jsonify({
                    "status": 700,
                    "message": "Invalid target user."
                })

        try:
            duration = int(duration)

            if duration < 0:
                raise ValueError

        except (ValueError, TypeError):
            return jsonify({
                "status": 700,
                "message": "Grant duration must be positive."
            })

        doc_path = os.path.join("documents", doc_id)

        metadata_path = doc_path + ".meta"

        if (not os.path.isfile(doc_path) or not os.path.isfile(metadata_path)):
            return jsonify({
                "status": 700,
                "message": "Document not found."
            })

        try:
            with open(metadata_path, "r", encoding = "utf-8") as metadata_file:
                metadata = json.load(metadata_file)

        except (OSError, ValueError):
            return jsonify({
                "status": 700,
                "message": "Unable to read document metadata."
            })

        # only doc owner can create grant
        if metadata.get("owner") != user_request:
            return jsonify({
                "status": 702,
                "message": "Access denied to grant access."
            })

        expiration_time = time.time() + duration

        metadata.pop("grants", None)

        metadata["grant"] = {
            "target-user": str(target_user),
            "access-right": int(access_right),
            "expires-at": expiration_time
        }

        try:
            with open(metadata_path, "w", encoding = "utf-8") as metadata_file:
                json.dump(metadata, metadata_file, indent = 4)

        except OSError:
            return jsonify({
                "status": 700,
                "message": "Unable to save grant."
            })

        return jsonify({
            "status": 200,
            "message": "Successfully granted access."
        })

class delete(Resource):
    # TODO: Implement delete functionality
    """
        Expected response status codes:
        1) 200 - Successfully deleted the file
        2) 702 - Access denied deleting file
        3) 704 - Delete failed since file not found on the server
        4) 700 - Other failures
    """
    def post(self):
        data = request.get_json(silent = True)

        if not data:
            return jsonify({
                "status": 700,
                "message": "Document deletion failed."
            })

        token = data.get("token")
        doc_id = data.get("document-id")
        user_id = active_sessions.get(token)

        if not user_id:
            return jsonify({
                "status": 702,
                "message": "Access denied deleting document."
            })

        if not doc_id:
            return jsonify({
                "status": 700,
                "message": "Document deletion failed."
            })

        if (os.path.basename(doc_id) != doc_id or os.path.isabs(doc_id)):
            return jsonify({
                "status": 700,
                "message": "Invalid document ID."
            })

        doc_path = os.path.join("documents", doc_id)

        metadata_path = doc_path + ".meta"

        if not os.path.isfile(metadata_path):
            return jsonify({
                "status": 704,
                "message": "Document not found."
            })

        try:
            with open(metadata_path, "r", encoding = "utf-8") as metadata_file:
                metadata = json.load(metadata_file)

        except (OSError, ValueError) as e:
            print(f"Unable to read deletion metadata: {e}")

            return jsonify({
                "status": 700,
                "message": "Document deletion failed."
            })

        # only original doc owner may delete the file
        if metadata.get("owner") != user_id:
            return jsonify({
                "status": 702,
                "message": "Access denied deleting document."
            })

        sec_flag = metadata.get("security-flag")
        encrypted_key_path = doc_path + ".key"
        nonce_path = doc_path + ".nonce"
        signature_path = doc_path + ".sig"

        # confidential files need to lose AES key first
        if sec_flag in {1, "1"}:
            if not destroy_key(encrypted_key_path):
                return jsonify({
                    "status": 700,
                    "message": "Document deletion failed because encryption key could not be destroyed."
                })

        deletion_targets = [doc_path, nonce_path, signature_path]

        # if key was already destroyed
        if sec_flag in {1, "1"}:
            deletion_targets.append(encrypted_key_path)

        for file_path in deletion_targets:
            if not remove_present_file(file_path):
                return jsonify({
                    "status": 700,
                    "message": "Document deletion failed."
                })

        # delete metadata
        if not remove_present_file(metadata_path):
            return jsonify({
                "status": 700,
                "message": "Document data was removed, but metadata deletion failed."
            })

        return jsonify({
            "status": 200,
            "message": "Document Successfully deleted"
        })

class logout(Resource):
    # TODO: Implement logout functionality
    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """

        data = request.get_json(silent = True)

        if not isinstance(data, dict):
            return jsonify({
                "status": 700,
                "message": "Logout failed."
            })


        token = data.get("token")

        if not isinstance(token, str) or not token:
            return jsonify({
                "status": 700,
                "message": "Logout failed."
            })
        
        # pop to check and remove token, future requests using this token are rejected
        removed_user = active_sessions.pop(token, None)

        if removed_user is None:
            return jsonify({
                "status": 700,
                "message": "Logout failed."
            })
        
        if user_sessions.get(removed_user) == token:
            user_sessions.pop(removed_user, None)

        return jsonify({
            "status": 200,
            "message": "Logout successful."
        })

api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')


def main():
    # You may add any server startup tasks here, such as 
    # instantiating a database, creating tables, etc.

    secure_shared_service.run(debug=True)       # DO NOT MODIFY

    # You may add any server cleanup tasks here

if __name__ == '__main__':
    main()
