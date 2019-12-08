'''
send and recv functions implementing the chatroom protocol
'''

import struct
import sys

# Make a global cipher_server won't work because different for each

def LNP_code(code):
    '''
    Decodes a negative integer into a msg and a string code
    '''

    if code == -1:
        return "Disconnected from the server.", "EXIT"
    if code == -2:
        return "Server is full.", "EXIT"
    if code == -3:
        return "Enter username, max 10 characters: ", "ACCEPT"
    if code == -4:
        return "", "USERNAME-ACCEPT"
    if code == -5:
        return "already in use", "USERNAME-TAKEN"
    if code == -6:
        return "Username is invalid. Enter username: ", "USERNAME-INVALID"
    if code == -7:
        return "\nConnection error. Disconnected from server.", "EXIT"
    if code == -8:
        return "", "NEED-CERTIFICATE"
    if code == -9:
        return "Username is not certified", "NOT-CERTIFIED"


def send(socket, msg, code=None, cipher=None):
    '''
    send a string. Code send command to client. Options are ["EXIT", ""]
    '''
    if code == "EXIT":
        socket.send(struct.pack('>i', -1))
    elif code == "FULL":
        socket.send(struct.pack('>i', -2))
    elif code == "ACCEPT":
        socket.send(struct.pack('>i', -3))
    elif code == "USERNAME-ACCEPT":
        socket.send(struct.pack('>i', -4))
    elif code == "USERNAME-TAKEN":
        socket.send(struct.pack('>i', -5))
    elif code == "USERNAME-INVALID":
        socket.send(struct.pack('>i', -6))
    elif code == "NEED-CERTIFICATE":
        socket.send(struct.pack('>i', -8))
    elif code == "NOT-CERTIFIED":
        socket.send(struct.pack('>i', -9))

    else: #no code, normal message
        utf_str = msg.encode('UTF-8')
        str_size = sys.getsizeof(utf_str)
        if str_size % 2 != 0:
            utf_str += b'0'
        packed_msg = struct.pack('>i{}s'.format(len(msg)), len(msg), utf_str)
        if cipher:
            repacked_msg = b''
            for byt in packed_msg:
                repacked_msg += cipher.encrypt(bytes([byt]))
            packed_msg = repacked_msg
        socket.send(packed_msg)


def recv(socket, msg_buffers, recv_len, msg_len, cipher_decrypter):
    '''
    function to read a byte stream and output the payload as a string
    s is socket, other arguments are dictionaries with socket keys
    returns a code with the status of the incoming message
    '''

    #initialize the msg buffer and recv_len if they dont exist
    if socket not in msg_buffers:
        msg_buffers[s] = b''
        recv_len[s] = 0

    try:
        msg = socket.recv(2)
        if cipher_decrypter: # make sure none doesn't pass this maybe check cipher_decrypted != None
            decrypted_msg = b''
            for byt in msg:
                decrypted_msg += cipher_decrypter.decrypt(bytes([byt]))
            msg = decrypted_msg


    # except:
    #     msg, code = LNP_code(-7)
    #     msg_buffers[s] = msg.encode('UTF-8')
    #     msg_len[s] = len(msg_buffers[s])
    #     return code

    except: # pylint: disable=W0702
        del msg_buffers[socket]
        del recv_len[socket]
        if socket in msg_len:
            del msg_len[socket]
        return "LOADING_MSG"

    if not msg:
        msg, code = LNP_code(-7)
        msg_buffers[s] = msg.encode('UTF-8')
        msg_len[s] = len(msg_buffers[socket])
        return code

    msg_buffers[socket] += msg
    recv_len[socket] += 2

    #if msg_length recieved:
    if (socket not in msg_len) and (recv_len[socket] == 4):

        length = struct.unpack(">i", msg_buffers[socket])[0]

        #Special codes are sent as negative numbers in the length field
        if length < 0:
            msg, code = LNP_code(length)
            msg_buffers[s] = msg.encode('UTF-8')
            msg_len[s] = len(msg_buffers[socket])
            return code

        msg_buffers[s] = b''
        recv_len[s] = 0
        msg_len[s] = length

    #if msg done buffering
    elif (socket in msg_len) and (recv_len[socket] >= msg_len[socket]):
        return "MSG_CMPLT"

    return "LOADING_MSG"


def get_msg_from_queue(socket, msg_buffers, recv_len, msg_len):
    '''
    reads the socket's buffered message and erases buffered message state variables
    '''
    recv_str = msg_buffers[socket]
    ret_str = recv_str.decode('UTF-8')

    del msg_buffers[socket]
    del recv_len[socket]
    del msg_len[socket]

    return ret_str
