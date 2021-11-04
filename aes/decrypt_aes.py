# Implementation based on FIPS AES Standard: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

import aes

def decrypt_message_cbc(blocks, keys, iv):
    previous_ciphertext = iv

    for i in range(len(blocks)):
        tmp = [row.copy() for row in blocks[i]]

        decrypt_block(blocks[i], keys)
        aes.add_round_key(blocks[i], previous_ciphertext) # XOR with previous ciphertext before decrypting

        previous_ciphertext = tmp

def decrypt_message_ecb(blocks, keys):
    for i in range(len(blocks)):
        decrypt_block(blocks[i], keys)

def decrypt_block(state, keys):
    aes.add_round_key(state, keys[aes.NUMBER_OF_ROUNDS * 4:((aes.NUMBER_OF_ROUNDS + 1) * 4)])

    for i in range(aes.NUMBER_OF_ROUNDS - 1, 0, -1):
        inv_shift_row(state)
        inv_sub_bytes(state)
        aes.add_round_key(state, keys[(i * 4):((i + 1) * 4)])
        inv_mix_columns(state)
        
    inv_shift_row(state)
    inv_sub_bytes(state)
    aes.add_round_key(state, keys[:4])

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = aes.ISBOX[state[i][j]]

def inv_shift_row(state):
    # first row: no shift

    # second row: shift 1 right
    state[1] = state[1][-1:] + state[1][:-1]

    # third row: shift 2 right
    state[2] = state[2][-2:] + state[2][:-2]

    # fouth row: shift 1 left
    state[3] = state[3][1:] + state[3][:1]

def inv_mix_columns(state):
    tmp = [row.copy() for row in state] # copy 2d state array
    
    for i in range(4):
        state[0][i] = aes.multiply_in_galois(0x0e, tmp[0][i]) ^ aes.multiply_in_galois(0x0b, tmp[1][i]) ^ aes.multiply_in_galois(0x0d, tmp[2][i]) ^ aes.multiply_in_galois(0x09, tmp[3][i])
        state[1][i] = aes.multiply_in_galois(0x09, tmp[0][i]) ^ aes.multiply_in_galois(0x0e, tmp[1][i]) ^ aes.multiply_in_galois(0x0b, tmp[2][i]) ^ aes.multiply_in_galois(0x0d, tmp[3][i])
        state[2][i] = aes.multiply_in_galois(0x0d, tmp[0][i]) ^ aes.multiply_in_galois(0x09, tmp[1][i]) ^ aes.multiply_in_galois(0x0e, tmp[2][i]) ^ aes.multiply_in_galois(0x0b, tmp[3][i])
        state[3][i] = aes.multiply_in_galois(0x0b, tmp[0][i]) ^ aes.multiply_in_galois(0x0d, tmp[1][i]) ^ aes.multiply_in_galois(0x09, tmp[2][i]) ^ aes.multiply_in_galois(0x0e, tmp[3][i])
