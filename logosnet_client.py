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

def is_private(msg):
    '''
    isPrivate returns username of recipient if the msg is private and None otherwise
    '''
    from_user = msg.split(' ')[1]
    to_user = msg.split(' ')[2]

    if to_user == '@':
        user = str1[1:len(str1)]
        return from_user, user

    return None, None

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

    sharedPrime = 23    # p
    sharedBase = 5      # g

    # Key will be username and value will be symmetric key
    dh_symmetric_keys = {}
    dh_client_secret = 0

    saved_messages = {}

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

                if code == "MSG_CMPLT":

                    # Check if private message
                    # If it is check if have sym key, if yes then encrypt
                    # If no then must be getting key so get it and make sym key and then send back over the line
                    from_user, to_user = is_private(msg)
                    if to_user is not None:
                        # then it is a private message


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

                    print(msg)
                    
                    str1 = msg.split(' ')[0]
                    if str1[0] == '@': # This is private message
                        user = str1[1:len(str1)]
                        if user in dh_symmetric_keys: # We have symmetric key for user
                            # do some decryption here
                            print(msg.split(' ')[1:])
                        else:
                            # setup values and send generated over
                            dh_client_secret = randint(0, 20)
                            A = (sharedBase ** dh_client_secret) % sharedPrime
                            saved_messages[user] = msg # save message to be send later?
                            # send this to next client
                            msg = '@' + user + ' ' + A

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
                    LNP.send(s, msg)

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()

if __name__ == '__main__':
    main()
