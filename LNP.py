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


def send(s, msg, code=None, cipher=None):
    '''
    send a string. Code send command to client. Options are ["EXIT", ""]
    '''
    if code == "EXIT":
        s.send(struct.pack('>i', -1))
    elif code == "FULL":
        s.send(struct.pack('>i', -2))
    elif code == "ACCEPT":
        s.send(struct.pack('>i', -3))
    elif code == "USERNAME-ACCEPT":
        s.send(struct.pack('>i', -4))
    elif code == "USERNAME-TAKEN":
        s.send(struct.pack('>i', -5))
    elif code == "USERNAME-INVALID":
        s.send(struct.pack('>i', -6))
    elif code == "NEED-CERTIFICATE":
        s.send(struct.pack('>i', -8))
    elif code == "NOT-CERTIFIED":
        s.send(struct.pack('>i', -9))

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
        
        s.send(packed_msg)


def recv(s, msg_buffers, recv_len, msg_len, cipher_decrypter):
    '''
    function to read a byte stream and output the payload as a string
    s is socket, other arguments are dictionaries with socket keys
    returns a code with the status of the incoming message
    '''

    #initialize the msg buffer and recv_len if they dont exist
    if s not in msg_buffers:
        msg_buffers[s] = b''
        recv_len[s] = 0

    try:
        msg = s.recv(2)
        if cipher_decrypter: # make sure none doesn't pass this maybe check cipher_decrypted != None
            decrypted_msg = b''
            for byt in msg:
                decrypted_msg += cipher_decrypter.decrypt(bytes([byt])) # then return cipher decrypter??
            msg = decrypted_msg


    # except:
    #     msg, code = LNP_code(-7)
    #     msg_buffers[s] = msg.encode('UTF-8')
    #     msg_len[s] = len(msg_buffers[s])
    #     return code

    except: # pylint: disable=W0702
        del msg_buffers[s]
        del recv_len[s]
        if s in msg_len:
            del msg_len[s]
        return "LOADING_MSG"
    
    if not msg:
        msg, code = LNP_code(-7)
        msg_buffers[s] = msg.encode('UTF-8')
        msg_len[s] = len(msg_buffers[s])
        return code

    msg_buffers[s] += msg
    recv_len[s] += 2

    #if msg_length recieved:
    if (s not in msg_len) and (recv_len[s] == 4):

        length = struct.unpack(">i", msg_buffers[s])[0]

        #Special codes are sent as negative numbers in the length field
        if length < 0:
            msg, code = LNP_code(length)
            msg_buffers[s] = msg.encode('UTF-8')
            msg_len[s] = len(msg_buffers[s])
            return code

        msg_buffers[s] = b''
        recv_len[s] = 0
        msg_len[s] = length

    #if msg done buffering
    elif (s in msg_len) and (recv_len[s] >= msg_len[s]):
        return "MSG_CMPLT"

    return "LOADING_MSG"


def get_msg_from_queue(s, msg_buffers, recv_len, msg_len):
    '''
    reads the socket's buffered message and erases buffered message state variables
    '''
    recv_str = msg_buffers[s]
    ret_str = recv_str.decode('UTF-8')

    del msg_buffers[s]
    del recv_len[s]
    del msg_len[s]

    return ret_str
