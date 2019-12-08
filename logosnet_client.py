'''
Gary Plunkett
Client for LogosNet assignment
Hosts a messageboard with up to 255 clients
'''

import argparse
import socket
import select
import queue
import sys
import LNP

import base64

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, ARC4
from Crypto.Hash import SHA
import random

def get_args():
    '''
    Gets command line argumnets.
    '''

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--port",
        metavar='p',
        dest='port',
        help="port number",
        type=int,
        default=42069
    )

    parser.add_argument(
        "--ip",
        metavar='i',
        dest='ip',
        help="IP address for client",
        default='127.0.0.1'
    )

    return parser.parse_args()

def readCertFile(name):
    '''
    Attempts to read the users .cert file and encodes it for sending
    Sends empty binary if the file does not exist
    '''
    name = name.strip('\n')
    cert = name + ".cert"
    try:
        with open(cert, 'rb') as certFile:
            content = certFile.read()
    except: # pylint: disable=W0702
        exit(1)

    encoded = base64.b64encode(content).decode()
    return encoded

def is_private(msg):
    '''
    isPrivate returns username of recipient if the msg is private and None otherwise
    '''

    # private message would look like > bob: @alice

    from_user = msg.split(' ')[1]
    from_user = from_user[:len(from_user)-1] # remove : from end
    to_user = msg.split(' ')[2]

    if to_user[0] == '@':
        user = to_user[1:len(to_user)]
        return from_user, user

    return None, None

def encrypted_message(msg, symmetric_key):
    encrypted_message = ''
    # print()
    for c in msg:
        # print(c)
        encrypted_message += chr(ord(c)+symmetric_key)

    return encrypted_message

def decrypted_message(msg, symmetric_key):
    decrypted_message = ''
    # print()
    for c in msg:
        # print(c)
        decrypted_message += chr(ord(c)-symmetric_key)

    return decrypted_message

#Main method
def main():
    '''
    uses a select loop to process user and server messages. Forwards user input to the server.
    '''

    args = get_args()
    server_addr = args.ip
    port = args.port

    server = socket.socket()
    server.connect((server_addr, port))

    msg_buffer = {}
    recv_len = {}
    msg_len = {}

    inputs = [server, sys.stdin]
    outputs = [server]
    message_queue = queue.Queue()

    waiting_accept = True
    username = ''
    username_next = False
    need_to_sign = False

    unverified_username = ''

    accepted_user = False

    symmetric_key = ''
    cipher = None
    do_not_send_msg = False

    sharedPrime = 23    # p
    sharedBase = 5      # g

    # Key will be username and value will be symmetric key
    dh_symmetric_keys = {}
    dh_client_secret = random.randint(0, 20)

    saved_messages = {}

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:

            ###
            ### Process server messages
            ###
            if s == server:

                code = ''

                if accepted_user:
                    code = LNP.recv(s, msg_buffer, recv_len, msg_len, cipher)
                else:
                    code = LNP.recv(s, msg_buffer, recv_len, msg_len, None)

                if code != "LOADING_MSG":
                    msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len, msg_len)
                    # print(code)

                if code == "MSG_CMPLT":

                    if symmetric_key == '':
                        public_key = msg
                        do_not_send_msg = True
                        # Save public key into client .pem file
                        client_public_key_file = open("client_rsa_public.pem", "w")
                        client_public_key_file.write(public_key)
                        client_public_key_file.close()

                        recipient_key = RSA.import_key(open("client_rsa_public.pem").read())
                        symmetric_key = get_random_bytes(16)

                        # Encrypt the session key with the public RSA key
                        cipher_rsa = PKCS1_OAEP.new(recipient_key)
                        enc_symmetric_key = cipher_rsa.encrypt(symmetric_key)

                        tempkey = SHA.new(symmetric_key).digest()
                        cipher = ARC4.new(tempkey)

                        #Now symmetric key is set
                        LNP.send(s, base64.b64encode(enc_symmetric_key).decode())

                    if msg.split(' ')[0] == "User" and msg.split(' ')[3] == "left":
                        # Removes sym_keys when the other user closes so when they rejoin
                        # a new set of keys is created
                        user_to_remove = msg.split(' ')[1]
                        del dh_symmetric_keys[user_to_remove]

                    establishing = False

                    # Check if private message
                    # If it is check if have sym key, if yes then encrypt
                    # If no then must be getting key so get it and make sym key
                    # and then send back over the line
                    # private message would look like > bob: @alice themessageee
                    # from_user bob to_user alice
                    from_user, to_user = is_private(msg)
                    if to_user is not None:
                        # then it is a private message
                        # check if setup connection between these clients before
                        if to_user != username:
                            # ignore
                            continue

                        elif from_user in dh_symmetric_keys:
                            # then we have a symmetric key, decrypt the message
                            # print("decrypted with dh_symmetric key")
                            decrypted_msg = decrypted_message(msg.split(' ', 3)[3],
                                dh_symmetric_keys[from_user])
                            # print(decrypted_msg)
                            msg = '> ' + str(from_user) + ': @' + str(to_user) + ' ' + str(decrypted_msg)
                            sys.stdout.write('\r' + msg + '\n')
                            sys.stdout.write("> " + username + ": ")
                            sys.stdout.flush()
                            # message_queue.put(msg)
                            # print(msg)
                        else:
                            establishing = True
                            # parse out the sent over symmetric key
                            #> bob: @alice A
                            A = int(msg.split(' ')[3])
                            dh_symmetric_key = (A**dh_client_secret) % sharedPrime
                            dh_symmetric_keys[from_user] = dh_symmetric_key
                            # print('dh_symmetric_key: ' + str(dh_symmetric_key))

                            if from_user in saved_messages:
                                # if client who is recieving now initiated private messages they will have a saved message
                                # send this message over now that connection is established
                                # check if saved message, if yes send that over

                                # encrypt the saved message with symmetric key
                                encrypted_msg = encrypted_message(saved_messages[from_user], dh_symmetric_keys[from_user])
                                msg = '@' + from_user + ' ' + str(encrypted_msg)

                                message_queue.put(msg)
                            else:
                                # client who is recieving now didn't initiate and needs to send key back over to one who did
                                # if no then generate own dh key and send it over
                                B = (sharedBase**dh_client_secret) % sharedPrime
                                # send this to next client
                                msg = '@' + from_user + ' ' + str(B)
                                message_queue.put(msg)

                    elif not establishing:

                        # Somewhere here check if private message and if so decrypt it.
                        if username_next:
                            username_msg = msg
                            username = username_msg.split(' ')[1]
                            sys.stdout.write(username_msg + '\n')
                            sys.stdout.write("> " + username + ": ")
                            sys.stdout.flush()
                            username_next = False

                        elif msg:
                    #If username exists, add message prompt to end of message
                            if username != '':
                                sys.stdout.write('\r' + msg + '\n')
                                sys.stdout.write("> " + username + ": ")
                                

                        
                            #If username doesnt exist, just write message
                            else:
                                sys.stdout.write(msg)

                            sys.stdout.flush()

                elif code == "ACCEPT":
                    waiting_accept = False
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                    need_to_sign = True
                
                elif code == "NEED-CERTIFICATE":
                    cert = readCertFile(unverified_username)
                    message_queue.put(cert)

                elif code == "USERNAME-INVALID" or code == "USERNAME-TAKEN":
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                elif code == "NOT-CERTIFIED":
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                    unverified_username = ''
                    need_to_sign = True

                elif code == "USERNAME-ACCEPT":
                    username_next = True
                    accepted_user = True

                elif code == "NO_MSG" or code == "EXIT":
                    sys.stdout.write(msg + '\n')
                    sys.stdout.flush()
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)

            ###
            ### Process user input
            ###
            else:

                msg = sys.stdin.readline()

                if need_to_sign:
                    unverified_username = msg
                    need_to_sign = False
                    sys.stdout.flush()

                if not waiting_accept:

                    msg = msg.rstrip()
                    
                    str1 = msg.split(' ')[0]
                    if len(str1) > 0 and str1[0] == '@': # This is private message
                        user = str1[1:len(str1)]
                        if user in dh_symmetric_keys: # We have symmetric key for user
                            # do some encryption here
                            # print('before encrypted with dh sym key message ' + str(msg.split(' ', 1)[1]))
                            msg = msg.split(' ', 1)[1]
                            encrypted_msg = encrypted_message(msg, dh_symmetric_keys[user])
                            # print(encrypted_msg)
                            msg = '@' + user + ' ' + str(encrypted_msg)
                        else:
                            # setup values and send generated over
                            A = (sharedBase ** dh_client_secret) % sharedPrime
                            saved_messages[user] = msg.split(' ', 1)[1] # save message to be send later?
                            # send this to next client
                            msg = '@' + user + ' ' + str(A)

                    # Check if message is private
                    # If private check if DH connection has been set up
                    # If yes then encrypt using symmetric key and send over
                    # If no then make secret, send value over, save value and message and wait for key to come back so we can encrypt msg and send off
                    
                    if msg:
                        message_queue.put(msg)
                    if not ((username == '') or (msg == "exit()")):
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()

        ###
        ### Send messages to server
        ###
        for s in writable:

            try:
                msg = message_queue.get_nowait()
            except queue.Empty:
                msg = None

	 #if there is a message to send
            if msg:

	     #if exit message, send the exit code
                if msg == "exit()":
                    outputs.remove(s)
                    LNP.send(s, '', "EXIT")

	     #otherwise just send the messsage
                else:
                    LNP.send(s, msg, None, cipher)

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()

if __name__ == '__main__':
    main()
