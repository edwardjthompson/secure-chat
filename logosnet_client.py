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

import os.path
from subprocess import check_output
import io
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

def sign(name):
    name = name.strip('\n')
    txt = name + ".txt"
    cert = name + ".cert"

    #make cert file for any user
    f = open(txt, 'w+')
    f.write(name + "\n")
    f.close()

    msg = check_output(["openssl", "dgst", "-sha256", "-sign", "ca-key-private.pem",
     "-out", cert, txt]).decode("utf-8")

    # print(msg)

def readCertFile(name):
    # print("name: " + name)
    name = name.strip('\n')
    cert = name + ".cert"
    try:
        with open(cert, 'rb') as certFile:
            content = certFile.read()
    except:
        content = b''
        

    encoded = base64.b64encode(content).decode()
    # print(encoded)
    # print()
    
    # print(content)
    # print()

    decoded = base64.b64decode(encoded)
    # print(decoded)
    return encoded

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

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:

            ###
            ### Process server messages
            ###
            if s == server:

                code = LNP.recv(s, msg_buffer, recv_len, msg_len)
                print(code)

                if code != "LOADING_MSG":
                    msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len, msg_len)

                if code == "MSG_CMPLT":

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
                    # Here is where the server wants the username
                    need_to_sign = True
                
                elif code == "NEED-CERTIFICATE":
                    #add cert file to msg_queue
                    # print(username)
                    cert = readCertFile(unverified_username)
                    # print(cert)
                    message_queue.put(cert)

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

                if need_to_sign:
                    # print(msg)
                    unverified_username = msg
                    sign(msg)
                    need_to_sign = False
                    sys.stdout.flush()

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
                    LNP.send(s, msg)

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()

if __name__ == '__main__':
    main()
