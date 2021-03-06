'''
Gary Plunkett
Server for LogosNet assignment
Hosts a messageboard with up to 100 clients
'''

import argparse
import socket
import select
import queue
import time
import LNP

import base64
from OpenSSL.crypto import load_publickey, FILETYPE_PEM, verify, X509

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, ARC4 
from Crypto.Hash import SHA

MAX_USR = 100
TIMEOUT = 60


def is_username(name, usernames, cert):
    '''
    Returns a string code with status of username
    '''
    if (len(name) < 1) or (len(name) > 10) or (' ' in name):
        return "USERNAME-INVALID"

    for s in usernames:
        if name == usernames[s]:
            return "USERNAME-TAKEN"

    v = verifyUser(name, cert)
    
    if not v:
        return "NOT-CERTIFIED"

    return "USERNAME-ACCEPT"


def is_private(msg, usernames):
    '''
    isPrivate returns username of recipient if the msg is private and None otherwise
    '''
    str1 = msg.split(' ')[0]

    if str1[0] == '@':

        user = str1[1:len(str1)]
        for sock in usernames:
            if usernames[sock] == user:
                return user

    return None


def broadcast_queue(msg, msg_queues, exclude=[]):
    '''
    broadcast_queue loads the message into every message queue,
    excluding sockets in the exclude array
    '''

    if msg and len(msg) <= 1000:
        for sock in msg_queues:
            if sock not in exclude:
                msg_queues[sock].put(msg)


def private_queue(msg, msg_queues, pvt_user, usernames):
    '''
    private_queue loads the message into the queue of the client with the username pvt_user
    '''
    for sock in msg_queues:
        if usernames[sock] == pvt_user:
            msg_queues[sock].put(msg)
            return


def get_args():
    '''
    get command-line arguments
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

    parser.add_argument(
        "--debug",
        help="turn on debugging messages",
        default=True,
        action="store_false"
    )

    return parser.parse_args()

def verifyUser(name, cert):
    '''
    Takes in the name and certificate and checks that the name matches
    the signature using the public key
    '''
    decoded = base64.b64decode(cert)

    with open("ca-key-public.pem", 'rb') as f:
        publicKey = f.read()

    pkey = load_publickey(FILETYPE_PEM, publicKey)

    x509 = X509()
    x509.set_pubkey(pkey)

    data = str.encode(name + "\n")

    try:
        verify(x509, decoded, data, 'sha256')
        return True
    except: # pylint: disable=W0702
        return False


def main():
    '''
    Main method. Loops forever until killed
    '''
    args = get_args()
    port = args.port
    ip = args.ip

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(0)
    server.bind((ip, port))
    server.listen(5)

    inputs = [server]
    outputs = []
    msg_queues = {}
    n_users = 0
    user_connect_time = {}

    #Dictionaries containing buffered messages and message state variable
    #Key for each is a socket object
    msg_buffers = {}
    recv_len = {}
    msg_len = {}
    usernames = {}
    unverified_usernames = {}
    symmetric_keys = {}
    ciphers = {}

    while inputs:

        #if 60 seconds are up no username yet, disconnect the client
        users = list(user_connect_time)
        for s in users:
            if (time.time() - user_connect_time[s]) > TIMEOUT:

                LNP.send(s, '', "EXIT")

                inputs.remove(s)
                outputs.remove(s)
                n_users -= 1
                del user_connect_time[s]


        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:

	    ###
	    ### Processing server connection requests
	    ###
            if s is server:

                connection, client_addr = s.accept()
                connection.setblocking(0)

                if n_users < MAX_USR:

                    #ciphers[s] = None

                    public_key = ''
                    with open('rsa_public.pem', 'r') as public_key_file:
                        public_key = public_key_file.read()
                        public_key.replace("\n", "").replace("\r", "")
                    LNP.send(connection, public_key) # send public key

                    time.sleep(.005)

                    LNP.send(connection, '', "ACCEPT")

                    #set up connnection variables
                    inputs.append(connection)
                    outputs.append(connection)
                    n_users += 1
                    user_connect_time[connection] = time.time()

                    if args.debug:
                        print("        SERVER: new connection from " + str(client_addr))

                else: #>100 users
                    LNP.send(connection, '', "FULL")
                    connection.close()

                    if args.debug:
                        print("        SERVER: connection from " +
                              str(client_addr) + " refused, server full")


	 ###
	 ### Processing client msgs
	 ###
            else:

                msg_status = None
                if s in ciphers:
                    msg_status = LNP.recv(s, msg_buffers, recv_len, msg_len, ciphers[s])
                else:
                    msg_status = LNP.recv(s, msg_buffers, recv_len, msg_len, None)

                if msg_status == "MSG_CMPLT":

                    msg = LNP.get_msg_from_queue(s, msg_buffers, recv_len, msg_len)

                    if args.debug:
                        print("        receieved " + str(msg) +	 " from " + str(s.getpeername()))
                    
                    if s not in symmetric_keys:
                        # decode symmetric key using server private key
                        enc_session_key = base64.b64decode(msg.encode())
                        
                        private_key = RSA.import_key(open("rsa_private.pem").read())
                        cipher_rsa = PKCS1_OAEP.new(private_key)
                        symmetric_key = cipher_rsa.decrypt(enc_session_key)
                        symmetric_keys[s] = symmetric_key

                        # make cipher and store it
                        tempkey = SHA.new(symmetric_key).digest()
                        cipher_server = ARC4.new(tempkey)
                        ciphers[s] = cipher_server


	         #Username exists for this client, this is a message
                    elif s in usernames:
                        pvt_user = is_private(msg, usernames)
                        msg = "> " + usernames[s] + ": " + msg
                        if pvt_user:
                            private_queue(msg, msg_queues, pvt_user, usernames)
                        else:
                            broadcast_queue(msg, msg_queues, exclude=[s])

                    elif s not in unverified_usernames:
                        unverified_usernames[s] = msg
                        LNP.send(s, '', "NEED-CERTIFICATE")


	         #no username yet, this message is a username
                    else:
                        username_status = is_username(unverified_usernames[s],
                        usernames, msg)

                        LNP.send(s, '', username_status)

                        if username_status == "USERNAME-ACCEPT":
                            usernames[s] = unverified_usernames[s]
                            del user_connect_time[s]
                            msg_queues[s] = queue.Queue()
                            msg = "User " + usernames[s] + " has joined"
                            print("        SERVER: " + msg)
                            broadcast_queue(msg, msg_queues)

                        else: #invalid username
                            user_connect_time[s] = time.time()
                            msg = None
                            del unverified_usernames[s]


	        ###
	        ### Closing connection with client
	        ###
                elif msg_status == "NO_MSG" or msg_status == "EXIT":

                    # if args.debug:
                    #     print("        SERVER: " + msg_status +
                    #           ": closing connection with " + str(s.getpeername()))

                    outputs.remove(s)
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)
                    if s in msg_queues:
                        del msg_queues[s]

	         #load disconnect message into msg_queues
                    if s in usernames:
                        for sock in msg_queues:
                            msg_queues[sock].put("User " + usernames[s] + " has left")
                        del usernames[s]

                    if s in user_connect_time:
                        del user_connect_time[s]

	         #If user sent disconnect message need to send one back
                    if msg_status == "EXIT":
                        LNP.send(s, '', "EXIT")

                    n_users -= 1
                    s.close()


        #Send messages to clients
        for s in writable:

            if s in msg_queues:

                try:
                    next_msg = msg_queues[s].get_nowait()

                except queue.Empty:
                    next_msg = None

                if next_msg:
                    if args.debug:
                        print("        sending " + next_msg + " to " + str(s.getpeername()))
                    LNP.send(s, next_msg, None, ciphers[s])


        #Remove exceptional sockets from the server
        for s in exceptional:

            if args.debug:
                print("        SERVER: handling exceptional condition for " + str(s.getpeername()))

            inputs.remove(s)
	 #if s in outputs:
            outputs.remove(s)
            del msg_queues[s]
            del usernames[s]
            s.close()


if __name__ == '__main__':
    main()
