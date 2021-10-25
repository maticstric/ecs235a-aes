import aes
import encrypt_aes

def main():
    aes.pad_message_array(aes.MESSAGE_ARRAY)

    print('\nplaintext (padded) message array:')
    aes.print_1d_hex(aes.MESSAGE_ARRAY)

    keys = aes.key_expansion(aes.KEY)
    blocks = aes.split_message_array_into_blocks(aes.MESSAGE_ARRAY)
    
    encrypt_aes.encrypt_message_ecb(blocks, keys)
    #encrypt_aes.encrypt_message_cbc(blocks, keys, aes.IV)


    cipher_message_array = aes.combine_blocks_into_message_array(blocks)

    print('\nciphertext message array:')
    aes.print_1d_hex(cipher_message_array)

    #encryptblocks = aes.split_message_array_into_blocks(cipher_message_array)

    decrypt_message_ecb(blocks, keys)
    #decrypt_message_cbc(blocks, keys, aes.IV)

    decipher_message_array = aes.combine_blocks_into_message_array(blocks)

    print('\nplaintext message array:')
    aes.print_1d_hex(decipher_message_array)

def decrypt_message_cbc(blocks, keys, iv):
    
    for i in range(len(blocks)-1, -1, -1):
        previous_ciphertext = [row.copy() for row in blocks[i]]
        decrypt_block(blocks[i], keys)

        if i == (len(blocks)-1):
            aes.add_round_key(blocks[i], iv)
        else:
            aes.add_round_key(blocks[i], previous_ciphertext)


def decrypt_message_ecb(blocks, keys):
    for i in range(len(blocks)):
        decrypt_block(blocks[i], keys)


def decrypt_block(inBytes, keys):
    state = inBytes

    aes.add_round_key(state, keys[aes.NUMBER_OF_ROUNDS * 4:((aes.NUMBER_OF_ROUNDS + 1) * 4)])

    for i in range(aes.NUMBER_OF_ROUNDS-1, 0, -1):
        inv_shift_row(state)
        inv_sub_bytes(state)
        aes.add_round_key(state, keys[(i * 4):((i+1)*4)])
        inv_mix_columns(state)
        
    inv_shift_row(state)
    inv_sub_bytes(state)
    aes.add_round_key(state, keys[0:4])

        

def inv_shift_row(state):
    # first row: no shift

    # second row: shift 1 right
    state[1] = state[1][-1:] + state[1][:-1]

    # third row: shift 2 right
    state[2] = state[2][-2:] + state[2][:-2]

    # fouth row: shift 1 left
    state[3] = state[3][1:] + state[3][:1]

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = aes.ISBOX[state[i][j]]

def inv_mix_columns(state):
    tmp = [row.copy() for row in state] # copy 2d state array
    
    for i in range(4):
        state[0][i] = aes.multiply_in_galois(0x0e, tmp[0][i]) ^ aes.multiply_in_galois(0x0b, tmp[1][i]) ^ aes.multiply_in_galois(0x0d, tmp[2][i]) ^ aes.multiply_in_galois(0x09, tmp[3][i])
        state[1][i] = aes.multiply_in_galois(0x09, tmp[0][i]) ^ aes.multiply_in_galois(0x0e, tmp[1][i]) ^ aes.multiply_in_galois(0x0b, tmp[2][i]) ^ aes.multiply_in_galois(0x0d, tmp[3][i])
        state[2][i] = aes.multiply_in_galois(0x0d, tmp[0][i]) ^ aes.multiply_in_galois(0x09, tmp[1][i]) ^ aes.multiply_in_galois(0x0e, tmp[2][i]) ^ aes.multiply_in_galois(0x0b, tmp[3][i])
        state[3][i] = aes.multiply_in_galois(0x0b, tmp[0][i]) ^ aes.multiply_in_galois(0x0d, tmp[1][i]) ^ aes.multiply_in_galois(0x09, tmp[2][i]) ^ aes.multiply_in_galois(0x0e, tmp[3][i])

if __name__=="__main__":
    main()
  
        