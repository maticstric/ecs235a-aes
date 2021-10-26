# SPN cipher taken from "Cryptography: Theory and Practice" by Douglas R. Stinson
# Differential cryptanalysis based on the same book

SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]

KEY1 = [0x7, 0x9, 0x0, 0x3]
KEY2 = [0xd, 0x1, 0x0, 0xf]
KEY3 = [0xd, 0x4, 0xd, 0xa]
KEY4 = [0x9, 0x2, 0x0, 0x2]
KEY5 = [0x7, 0x6, 0xc, 0xb]

def main():
    state = [0xa, 0x6, 0xf, 0x1]

    print_1d_hex(state)

    encrypt(state)

    print_1d_hex(state)


""" SPN Cipher """

def encrypt(state):
    add_round_key(state, KEY1)
    substitute(state)
    permutate(state)

    add_round_key(state, KEY2)
    substitute(state)
    permutate(state)

    add_round_key(state, KEY2)
    substitute(state)
    permutate(state)

    add_round_key(state, KEY4)
    substitute(state)

    add_round_key(state, KEY5)

def substitute(state):
    # state = array of nibbles, not bytes  
    for i in range(len(state)):
        state[i] = SBOX[state[i]]

def permutate(state):
    # state = array of nibbles, not bytes  
    tmp = state.copy()

    state[0] = (tmp[0] & 0x8) + ((tmp[1] & 0x8) >> 1) + ((tmp[2] & 0x8) >> 2) + ((tmp[3] & 0x8) >> 3)
    state[1] = ((tmp[0] & 0x4) << 1) + (tmp[1] & 0x4) + ((tmp[2] & 0x4) >> 1) + ((tmp[3] & 0x4) >> 2)
    state[2] = ((tmp[0] & 0x2) << 2) + ((tmp[1] & 0x2) << 1) + (tmp[2] & 0x2) + ((tmp[3] & 0x2) >> 1)
    state[3] = ((tmp[0] & 0x1) << 3) + ((tmp[1] & 0x1) << 2) + ((tmp[2] & 0x1) << 1) + (tmp[3] & 0x1)

def add_round_key(state, key):
    # state, key = array of nibbles, not bytes  

    for i in range(len(key)):
        state[i] = state[i] ^ key[i]

# Normal printing is going to print integers in decimal. For debugging, hex is much easier
def print_1d_hex(arr):
    string = '['

    for i in range(len(arr)):
        string += '{:#04x}'.format(arr[i]) + ', '

    string = string[:-2] # remove the ', ' from last element
    string += ']'

    print(string)
    
if __name__=="__main__":
    main()
