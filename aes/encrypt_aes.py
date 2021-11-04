# Implementation based on FIPS AES Standard: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

import aes

def encrypt_message_cbc(blocks, keys, iv):
    for i in range(len(blocks)):
        previous_ciphertext = iv if i == 0 else blocks[i - 1]

        aes.add_round_key(blocks[i], previous_ciphertext) # XOR with previous ciphertext before encrypting
        encrypt_block(blocks[i], keys)

def encrypt_message_ecb(blocks, keys):
    for i in range(len(blocks)):
        encrypt_block(blocks[i], keys)

def encrypt_block(state, keys):
    aes.add_round_key(state, keys[:4])

    for i in range(1, aes.NUMBER_OF_ROUNDS):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        aes.add_round_key(state, keys[(i * 4):(i * 4 + 4)])

    sub_bytes(state)
    shift_rows(state)
    aes.add_round_key(state, keys[aes.NUMBER_OF_ROUNDS * 4:((aes.NUMBER_OF_ROUNDS + 1) * 4)])

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = aes.SBOX[state[i][j]]

def shift_rows(state):
    # first row: no shift

    # second row: shift 1 left
    state[1] = state[1][1:] + state[1][:1]

    # third row: shift 2 left
    state[2] = state[2][2:] + state[2][:2]

    # fourth row: shift 3 left (equal to 1 right)
    state[3] = state[3][-1:] + state[3][:-1]

def mix_columns(state):
    tmp = [row.copy() for row in state] # copy 2d state array
    
    for i in range(4):
        state[0][i] = aes.multiply_in_galois(0x02, tmp[0][i]) ^ aes.multiply_in_galois(0x03, tmp[1][i]) ^ tmp[2][i] ^ tmp[3][i]
        state[1][i] = tmp[0][i] ^ aes.multiply_in_galois(0x02, tmp[1][i]) ^ aes.multiply_in_galois(0x03, tmp[2][i]) ^ tmp[3][i]
        state[2][i] = tmp[0][i] ^ tmp[1][i] ^ aes.multiply_in_galois(0x02, tmp[2][i]) ^ aes.multiply_in_galois(0x03, tmp[3][i])
        state[3][i] = aes.multiply_in_galois(0x03, tmp[0][i]) ^ tmp[1][i] ^ tmp[2][i] ^ aes.multiply_in_galois(0x02, tmp[3][i])
