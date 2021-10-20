# AES

# Implementation based on FIPS AES Standard: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

import math

KEY_LENGTH = 4 # in words (32 bits)
NUMBER_OF_ROUNDS = 10

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

RCON = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

def main():
    key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    message_array = [0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34, 0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8]

    pad_message_array(message_array)

    keys = key_expansion(key)
    blocks = split_message_array_into_blocks(message_array)

    print('plaintext blocks:')
    for b in blocks:
        print_2d_hex(b)

    encrypt_message(blocks, keys)

    print('--------------------------\nciphertext blocks:')
    for b in blocks:
        print_2d_hex(b)

def encrypt_message(blocks, keys):
    for i in range(len(blocks)):
        encrypt_block(blocks[i], keys)

def encrypt_block(state, keys):
    add_round_key(state, keys[:4])

    for i in range(1, NUMBER_OF_ROUNDS):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, keys[(i * 4):(i * 4 + 4)])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, keys[NUMBER_OF_ROUNDS * 4:((NUMBER_OF_ROUNDS + 1) * 4)])

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]

def shift_rows(state):
    # first row: no shift

    # second row: shift 1 left
    state[1] = state[1][1:] + state[1][:1]

    # third row: shift 2 left
    state[2] = state[2][2:] + state[2][:2]

    # fouth row: shift 3 left (equal to 1 right)
    state[3] = state[3][-1:] + state[3][0:-1]

def mix_columns(state):
    tmp = [row.copy() for row in state] # copy 2d state array
    
    for i in range(4):
        state[0][i] = multiply_in_galois(0x02, tmp[0][i]) ^ multiply_in_galois(0x03, tmp[1][i]) ^ tmp[2][i] ^ tmp[3][i]
        state[1][i] = tmp[0][i] ^ multiply_in_galois(0x02, tmp[1][i]) ^ multiply_in_galois(0x03, tmp[2][i]) ^ tmp[3][i]
        state[2][i] = tmp[0][i] ^ tmp[1][i] ^ multiply_in_galois(0x02, tmp[2][i]) ^ multiply_in_galois(0x03, tmp[3][i])
        state[3][i] = multiply_in_galois(0x03, tmp[0][i]) ^ tmp[1][i] ^ tmp[2][i] ^ multiply_in_galois(0x02, tmp[3][i])

def add_round_key(state, key):
    for i in range(4):
        for j in range(4):
            # j and i flipped intentionally since it's column-major order
            state[j][i] ^= key[i][j]

def key_expansion(key):
    keys = []

    i = 0

    while (i < KEY_LENGTH):
        keys.append([ key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3] ])

        i += 1

    i = KEY_LENGTH

    while (i < 4 * (NUMBER_OF_ROUNDS + 1)):
        temp = keys[i - 1]
            
        if (i % KEY_LENGTH == 0):
            temp = xor_words(sub_word(rot_word(temp)), RCON[(i // KEY_LENGTH) - 1])
        elif (KEY_LENGTH > 6 and i % KEY_LENGTH == 4):
            temp = sub_word(temp)

        keys.append(xor_words(keys[i - KEY_LENGTH], temp))

        i += 1

    return keys

# OneAndZeroes padding
def pad_message_array(message_array): # message_array is array of bytes
    bytes_missing = 16 - len(message_array) % 16

    if bytes_missing > 0 and bytes_missing < 16: # if len(message_array) = 16 then bytes_missing = 16, so we need to check that bytes_missing < 16
        message_array.append(0x80)

        for i in range(bytes_missing - 1):
            message_array.append(0x00)

def split_message_array_into_blocks(message_array):
    blocks = []

    for i in range(math.ceil(len(message_array) / 16)):
        block = []

        for j in range(i * 4, (i + 1) * 4):
            block.append(message_array[(j * 4):((j + 1) * 4)])

        blocks.append(block)

    return blocks

def sub_word(word): # word is 4 bytes, in array length 4
    sub_word = []

    for i in range(4):
        sub_word.append(SBOX[word[i]])

    return sub_word

def rot_word(word): # word is 4 bytes, in array length 4
    rot_word = []

    rot_word = word[1:] + word[:1]

    return rot_word

def xor_words(w1, w2): # word is 4 bytes, in array length 4
    xor_word = []

    for i in range(4):
        xor_word.append(w1[i] ^ w2[i])

    return xor_word

# MixColumns requires the multiplication to be done in GF(2^8). Inputs should be bytes
# Peasant's Algorithm: https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
def multiply_in_galois(a, b):
    p = 0 # final product

    for i in range(8): # once per bit
        if b & 1 == 1:
            p ^= a

        b = b >> 1

        carry = 1 if (a & 0x80 == 0x80) else 0

        a = a << 1

        if carry == 1:
            a ^= 0x1b

    return p % 256

# Normal printing is going to print integers in decimal. For debugging, hex is much easier
def print_2d_hex(arr):
    string = '[\n'

    for i in range(len(arr)):
        string += '  ['
        for j in range(len(arr[i])):
            string += '{:#04x}'.format(arr[i][j]) + ', '

        string = string[:-2] # remove the ', ' from last element
        string += ']\n'

    string += ']'

    print(string)

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
