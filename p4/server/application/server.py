''' 
Implement the 3DS Server. You may import additional modules as required from 
the the Python standard libraries or requirements.txt file provided on Github, 
as needed. 

When referencing files or directories, always use relative paths - do NOT hard 
code absolute paths.
'''

from flask import Flask, request, jsonify
from flask_restful import Resource, Api
''' 
TODO: import additional modules as required from requirements.txt or the 
python standard library.
'''
import base64
import json


secure_shared_service = Flask(__name__)     # DO NOT MODIFY
api = Api(secure_shared_service)            # DO NOT MODIFY


class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"

def verify_statement(statement, signed_statement, user_public_key_file):
    # TODO: Implement verify statement functionality

    return False


class login(Resource):
    def post(self):
        data = request.get_json()
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
        user_id = data['user-id']
        statement = data['statement']
        signed_statement = base64.b64decode(data['signed-statement'])

        # complete the relative path of the user public key filename
        # ./userpublickeys/{user_public_key_filename}
        user_public_key_file = './userpublickeys/' + user_id + '.pub'

        success = verify_statement(statement, signed_statement, user_public_key_file)

        if success:
            session_token = 'ABCD'
            # Similar response format given below can be used for all the other functions
            response = {
                'status': 200,
                'message': 'Login Successful',
                'session_token': session_token,
            }
        else:
            response = {
                'status': 700,
                'message': 'Login Failed',
                'session_token': "INVALID",
            }
        return jsonify(response)


class checkin(Resource):
    # TODO: Implement checkin functionality
    """
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    3) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        token = data['token']
        success = False
        if success:
            response = {
                'status': 200,
                'message': 'Document Successfully checked in',
            }
        else:
            response = {
                'status': 702,
                'message': 'Access denied checking in',
            }
        return jsonify(response)


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
        data = request.get_json()
        token = data['token']
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Document Successfully checked out',
                'file': 'file',
            }
        else:
            response = {
                'status': 702,
                'message': 'Access denied checking out',
                'file': 'Invalid',
            }
        return jsonify(response)

class grant(Resource):
    # TODO: Implement grant functionality
    """
        Expected response status codes:
        1) 200 - Successfully granted access
        2) 702 - Access denied to grant access
        3) 700 - Other failures
    """
    def post(self):
        data = request.get_json()
        token = data['token']
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Successfully granted access',
            }
        else:
            response = {
                'status': 702,
                'message': 'Access denied to grant access',
            }
        return jsonify(response)


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
        data = request.get_json()
        token = data['token']
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Successfully deleted the file',
            }
        else:
            response = {
                'status': 702,
                'message': 'Access denied deleting file',
            }
        return jsonify(response)


class logout(Resource):
    # TODO: Implement logout functionality
    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """

        def post(self):
            data = request.get_json()
            token = data['token']
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Successfully logged out',
            }
        else:
            response = {
                'status': 700,
                'message': 'Failed to log out',
            }
        return jsonify(response)



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
