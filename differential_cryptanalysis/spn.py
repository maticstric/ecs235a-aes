# SPN cipher taken from "Cryptography: Theory and Practice" by Douglas R. Stinson
# Differential cryptanalysis based on the same book

import random
import heapq

SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
INV_SBOX = [0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5]

KEY1 = [0x7, 0x9, 0x0, 0x3]
KEY2 = [0xd, 0x1, 0x0, 0xf]
KEY3 = [0xd, 0x4, 0xd, 0xa]
KEY4 = [0x9, 0x2, 0x0, 0x2]
KEY5 = [0x8, 0x6, 0xc, 0xb]

def main():
    #state = [0xa, 0x6, 0xf, 0x1]
    #print_1d_hex(state)
    #encrypt(state)
    #print_1d_hex(state)
    #decrypt(state)
    #print_1d_hex(state)

    diff_dist_table = build_difference_distribution_table(SBOX)

    round_num = 3
    num_of_diff_trails = 100

    most_probable_differential_trails = find_most_probable_differential_trails(diff_dist_table, round_num, num_of_diff_trails)

    round_key = break_round_key(round_num, most_probable_differential_trails)

    print_1d_hex(round_key)

def break_round_key(round_num, most_probable_differential_trails):
    key_nibbles_broken = [False, False, False, False] # Which key nibbles we have broken. Initially none
    round_key = [0, 0, 0, 0]

    while not all(key_nibbles_broken):
        useful_diff_trail = find_useful_diff_trail(most_probable_differential_trails, key_nibbles_broken)
        print(useful_diff_trail)

        input_xor = useful_diff_trail[1]
        most_probable_output_xor = useful_diff_trail[2]

        broken_key_nibbles = break_key_nibbles(round_num, input_xor, most_probable_output_xor)

        # Set the round key and mark which key nibbles this broke
        for i in range(4):
            if broken_key_nibbles[i] != 0:
                round_key[i] = broken_key_nibbles[i]
                key_nibbles_broken[i] = True

    return round_key

def break_key_nibbles(round_num, input_xor, most_probable_output_xor):
    key_count_dict = {}

    # We need some number of random chosen plaintexts.
    # This number is pulled out of thin air. It seems to work well, and is still fairly quick
    for i in range(1000):
        text1 = choose_random_plaintext()
        text2 = xor(text1, input_xor)

        # Now, text1 ^ text2 = input_xor and we can encrypt both

        encrypt(text1)
        encrypt(text2)

        # This will modify the key_count_dict after key guesses
        guess_key_nibbles(round_num, text1, text2, most_probable_output_xor, key_count_dict)

    # Extract the most likely key out of the dictonary
    most_probable_key = sorted(key_count_dict.items(), key=lambda x: x[1], reverse=True)[0][0]

    # Put key back into list form, since it was a string in the dict
    final_key_guess = list(map(int, most_probable_key.split(' ')))

    return final_key_guess

def guess_key_nibbles(round_num, ciphertext1, ciphertext2, most_probable_output_xor, key_count_dict):
    active_sboxes = [0, 0, 0, 0] # Which sboxes are active, represented with either a zero or a one

    for i in range(4):
        if most_probable_output_xor[i] != 0:
            active_sboxes[i] = 1

    # Only loop through the possible key values for the places where the sboxes are active
    i_loop_value = 16 * active_sboxes[0] if active_sboxes[0] == 1 else 1
    j_loop_value = 16 * active_sboxes[1] if active_sboxes[1] == 1 else 1
    k_loop_value = 16 * active_sboxes[2] if active_sboxes[2] == 1 else 1
    l_loop_value = 16 * active_sboxes[3] if active_sboxes[3] == 1 else 1

    for i in range(i_loop_value):
        for j in range(j_loop_value):
            for k in range(k_loop_value):
                for l in range(l_loop_value):
                    key = [i, j, k, l]
                    key_as_string = ' '.join(map(str, key))

                    partial_xor = partial_decryption(round_num, key, ciphertext1, ciphertext2)

                    if partial_xor == most_probable_output_xor:
                        if key_as_string not in key_count_dict:
                            key_count_dict[key_as_string] = 1
                        else:
                            key_count_dict[key_as_string] += 1

def partial_decryption(round_num, key, ciphertext1, ciphertext2):
    partially_decrypted1 = xor(ciphertext1, key)
    partially_decrypted2 = xor(ciphertext2, key)

    inv_substitute(partially_decrypted1)
    inv_substitute(partially_decrypted2)

    return xor(partially_decrypted1, partially_decrypted2)

def find_useful_diff_trail(most_probable_differential_trails, key_nibbles_broken):
    for diff_trail in most_probable_differential_trails:
        most_probable_output_xor = diff_trail[2]

        # Check if this diff_trail will help us break any key nibbles we haven't broken before
        for i in range(4):
            if most_probable_output_xor[i] != 0 and key_nibbles_broken[i] == False: # Hit! We can use this one
                return diff_trail

def find_most_probable_differential_trails(diff_dist_table, round_num, num_of_diff_trails):
    differential_trails = []

    for i in range(16):
        for j in range(16):
            for k in range(16):
                for l in range(16):
                    if i == 0 and j == 0 and k == 0 and l == 0: continue # We don't care about all zero xors

                    input_xor = [i, j, k, l]
                    most_probable_output_xor, probability = find_differential_trail(input_xor, diff_dist_table, round_num)

                    # Python doesn't provide a max heap (...) so the probabilites are made negative so the largest are on top
                    differential_trails.append((probability, input_xor, most_probable_output_xor))

    differential_trails.sort(reverse=True)

    return differential_trails[:num_of_diff_trails]

def find_differential_trail(input_xor, diff_dist_table, num_of_rounds):
    probability = 1
    active_sboxes = [False, False, False, False] # bool array of which sboxes are active

    current_xor = input_xor.copy()

    for r in range(num_of_rounds):
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

    return (current_xor, probability)

def build_difference_distribution_table(sbox):
    diff_dist_table = [[0 for i in range(len(sbox))] for j in range(len(sbox))]

    for x_prime in range(16):
        for x in range(16):
            x_star = x ^ x_prime
            y_prime = sbox[x] ^ sbox[x_star]

            diff_dist_table[x_prime][y_prime] += 1

    return diff_dist_table

def choose_random_plaintext():
    return [random.randrange(16) for n in range(4)]

def xor(p1, p2):
    xor = []

    for i in range(len(p1)):
        xor.append(p1[i] ^ p2[i])

    return xor

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
