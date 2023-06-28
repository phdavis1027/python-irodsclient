## standard imports
import logging
import json
import hashlib
import struct
import base64

## iRODS imports
from irods.message import (
    JSON_Binary_Request, 
    iRODSMessage
)
from irods import MAX_PASSWORD_LENGTH
from irods.api_number import api_number 

## Third-party imports
import six


logger = logging.getLogger(__name__)

def login(conn, password=None):
    if password is None:
        password = conn.account.password or ''

    ## Prepare the messasge
    auth_ctx = {"a_ttl":"0",
                "force_password_prompt":"true",
                "next_operation":"auth_agent_auth_request",
                "scheme":"native",
                "user_name":"rods",
                "zone_name":"tempZone"}
    initial_authentication_msg = JSON_Binary_Request(auth_ctx)
    msg = iRODSMessage(msg_type='RODS_API_REQ', 
                       int_info=api_number['AUTHENTICATION_APN'], 
                       msg=initial_authentication_msg)

    ## Send the message
    conn.send(msg)

    challenge_msg = conn.recv()
    logger.debug(challenge_msg.msg)
    ## Update the auth context 
    auth_ctx = challenge_msg.get_json_encoded_struct()
    
    ## Pad the password. Necessary for server bc it's written in C,
    ## so fixed-size arrays.
    if six.PY3:
        padded_password = struct.pack(
            "%ds" % MAX_PASSWORD_LENGTH, password.encode(
                'utf-8').strip())
    else:
        padded_password = struct.pack(
            "%ds" % MAX_PASSWORD_LENGTH, password)

    ## Rise to the challenege
    challenge_string = auth_ctx['request_result']
    print("[PRC] CHALLENGE STRING")
    print(challenge_string)
    ## I don't understand why the ">" is necessary, but it looks lik it's fixed in Python .0
    ## See here: https://stackoverflow.com/questions/36044676/text-formatting-error-alignment-not-allowed-in-string-format-specifier
    if six.PY2:
        conn._client_signature = "".join("{:0>2s}".format(ord(c)) for c in challenge_string[:16])
    else:
        conn._client_signature = "".join("{:0>2s}".format(c) for c in challenge_string[:16])

    m = hashlib.md5()
    m.update(challenge_string.strip().encode('utf-8'))
    m.update(padded_password)
    hash = m.digest()

    ## TODO: Figure out why this is necessary
    ## see: https://github.com/irods/python-irodsclient/blob/main/irods/connection.py#L560
    if six.PY2:
        hash = hash.replace('\x00', '\x01')
    elif b'\x00' in hash:
        hash_array = bytearray(hash)
        hash = bytes(hash_array.replace(b'\x00', b'\x01'))

    challenge_response = base64.b64encode(
        hash
    ).decode('utf-8')
    
    ## Let the server know 
    auth_ctx['digest'] = challenge_response
    auth_ctx['next_operation'] = 'auth_agent_auth_response'
    challenge_response_msg = JSON_Binary_Request(auth_ctx)
    msg = iRODSMessage(msg_type='RODS_API_REQ',
                       int_info=api_number['AUTHENTICATION_APN'],
                       msg=challenge_response_msg)
    conn.send(msg)

    ## Is the server happy? recv() throws exception if not
    conn.recv()
