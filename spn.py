# SPN cipher taken from "Cryptography: Theory and Practice" by Douglas R. Stinson
# Differential cryptanalysis based on the same book

SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
INV_SBOX = [0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5]

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

    decrypt(state)

    print_1d_hex(state)

    diff_dist_table = build_difference_distribution_table(SBOX)

    find_differential_trail([0xb, 0x0, 0xb, 0x0], diff_dist_table)

def find_differential_trail(input_xor, diff_dist_table):
    probability = 1
    active_sboxes = [False, False, False, False] # bool array of which sboxes are active
    current_xor = input_xor.copy()

    for r in range(3):
        for i in range(len(current_xor)):
            if current_xor[i] > 0: active_sboxes[i] = True
            else: active_sboxes[i] = False

        # XOR going through the sbox (source of nonlinearity)
        for i in range(len(active_sboxes)):
            if active_sboxes[i]:
                max_probability = max(diff_dist_table[current_xor[i]])
                most_probable_output_xor = diff_dist_table[current_xor[i]].index(max_probability)

                probability *= max_probability / len(diff_dist_table)
                
                current_xor[i] = most_probable_output_xor

        # XOR going through the permutation (linear)
        permutate(current_xor)
    
    print(probability)

def build_difference_distribution_table(sbox):
    diff_dist_table = [[0 for i in range(len(sbox))] for j in range(len(sbox))]

    for x_prime in range(16):
        for x in range(16):
            x_star = x ^ x_prime
            y_prime = sbox[x] ^ sbox[x_star]

            diff_dist_table[x_prime][y_prime] += 1

    return diff_dist_table


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

def decrypt(state):
    add_round_key(state, KEY5)

    inv_substitute(state)
    add_round_key(state, KEY4)

    inv_permutate(state)
    inv_substitute(state)
    add_round_key(state, KEY2)

    inv_permutate(state)
    inv_substitute(state)
    add_round_key(state, KEY2)

    inv_permutate(state)
    inv_substitute(state)
    add_round_key(state, KEY1)

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

def inv_substitute(state):
    # state = array of nibbles, not bytes  
    for i in range(len(state)):
        state[i] = INV_SBOX[state[i]]

def inv_permutate(state): # In the specific case of this permutation box, inv is the same
    permutate(state)

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
