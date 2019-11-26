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

import asymcrypt
from cryptography.fernet import Fernet
import base64

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

    # Here do encryption stuff, client just connected to server
    # code = LNP.recv(server, msg_buffer, recv_len, msg_len)

    inputs = [server, sys.stdin]
    outputs = [server]
    message_queue = queue.Queue()

    waiting_accept = True
    username = ''
    username_next = False

    symmetric_key = ''

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:

            ###
            ### Process server messages
            ###
            if s == server:

                code = LNP.recv(s, msg_buffer, recv_len, msg_len)

                if code != "LOADING_MSG":
                    msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len, msg_len)

                #print(msg)

                if code == "MSG_CMPLT":
                    
                    #print(msg)
                    if symmetric_key != '':
                        f = Fernet(symmetric_key)
                        msg = f.decrypt(msg.encode())
                        #print(msg)

                    if symmetric_key == '':
                        symmetric_key = Fernet.generate_key()
                        #print(symmetric_key)
                        #print(msg) # This should be public key
                        public_key = msg
                        # Save public key into client .pem file
                        client_public_key_file = open("client_rsa_public.pem", "w")
                        client_public_key_file.write(public_key)
                        client_public_key_file.close()

                        # encrpyt symmetric key with public key
                        encrypted_symmetric_key = asymcrypt.encrypt_data(symmetric_key,'client_rsa_public.pem')
                        #print("Encrypted sym key")
                        #print(encrypted_symmetric_key)
                        decrypted_symmetric_key = asymcrypt.decrypt_data(encrypted_symmetric_key,'rsa_private.pem')
                        #print("\nDecrypted sym key")
                        #print(decrypted_symmetric_key)

                        f = Fernet(symmetric_key)
                        encrypted = f.encrypt("yeet".encode())
                        decrypted = f.decrypt(encrypted)
                        #print(decrypted.decode())

                        #print(base64.b64encode(encrypted_symmetric_key))

                        overtheline = base64.b64encode(encrypted_symmetric_key).decode()
                        #print(overtheline)

                        backback = base64.b64decode(overtheline.encode())
                        #print(backback)

                        LNP.send(s, overtheline)

                    elif username_next:
                        username_msg = msg
                        print(username_msg)
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

                elif code == "USERNAME-INVALID" or code == "USERNAME-TAKEN":
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                elif code == "USERNAME-ACCEPT":
                    username_next = True

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

                if not waiting_accept:
                    msg = msg.rstrip()
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
                    LNP.send(s, msg, None, symmetric_key)

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()

if __name__ == '__main__':
    main()
