# SPN cipher taken from "Cryptography: Theory and Practice" by Douglas R. Stinson
# Differential cryptanalysis based on the same book

import random

#SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
#INV_SBOX = [0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5]
#PBOX = [0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf]
#INV_PBOX = [0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf] # PBOX and INV_PBOX are the same in this case

SBOX = [0x6, 0xd, 0x1, 0xf, 0x7, 0xc, 0x8, 0x3, 0x2, 0x0, 0xe, 0xa, 0x5, 0x9, 0xb, 0x4]
INV_SBOX = [0x9, 0x2, 0x8, 0x7, 0xf, 0xc, 0x0, 0x4, 0x6, 0xd, 0xb, 0xe, 0x5, 0x1, 0xa, 0x3]
PBOX = [0x5, 0x9, 0x0, 0xc, 0x7, 0x3, 0xb, 0xe, 0x1, 0x4, 0xd, 0x8, 0x2, 0xf, 0x6, 0xa]
INV_PBOX = [0x2, 0x8, 0xc, 0x5, 0x9, 0x0, 0xe, 0x4, 0xb, 0x1, 0xf, 0x6, 0x3, 0xa, 0x7, 0xd]

KEY0 = [0x7, 0x9, 0x0, 0x3]
KEY1 = [0xd, 0x1, 0x0, 0xf]
KEY2 = [0xd, 0x4, 0xd, 0xa]
KEY3 = [0x9, 0x2, 0x0, 0x2]
KEY4 = [0x8, 0x6, 0xc, 0xb]

#KEY0 = [0xc, 0x2, 0xe, 0x0]
#KEY1 = [0x4, 0xc, 0xf, 0x4]
#KEY2 = [0xe, 0x6, 0x4, 0x0]
#KEY3 = [0x9, 0x7, 0xd, 0x9]
#KEY4 = [0x4, 0xb, 0x4, 0x5]

def main():
    diff_dist_table = build_difference_distribution_table(SBOX)

    round_keys = [[], [], [], [], []]
    num_of_diff_trails = 100


    # Get the last 4 keys
    for round_num in range(3, -1, -1):
        print('--- Breaking KEY' + str(round_num + 1) + ' ---')
        print('Finding most probable differential trails for KEY' + str(round_num + 1) + '...')
        most_probable_differential_trails = find_most_probable_differential_trails(diff_dist_table, round_num, num_of_diff_trails)
        round_keys[round_num + 1] = break_round_key(round_num, most_probable_differential_trails, round_keys)
        print('\n')

    # Get the first key
    print('--- Breaking KEY0 ---')
    round_keys[0] = break_first_round_key(round_keys)
    print('*************************************')
    print('Found KEY0 = ' + get_string_1d_hex(round_keys[0]))
    print('*************************************')

    print('\nFound all round keys!\n') 

    print('*********************************')
    print('  KEY0 = ' + get_string_1d_hex(round_keys[0]))
    print('  KEY1 = ' + get_string_1d_hex(round_keys[1]))
    print('  KEY2 = ' + get_string_1d_hex(round_keys[2]))
    print('  KEY3 = ' + get_string_1d_hex(round_keys[3]))
    print('  KEY4 = ' + get_string_1d_hex(round_keys[4]))
    print('*********************************')



""" START OF DIFFERENTIAL CRYPTANALYSIS OF SPN """

def break_round_key(round_num, most_probable_differential_trails, round_keys):
    round_key = [0] * 16 # We'll be building this round key
    sboxes_already_used = [False, False, False, False]

    while not all(sboxes_already_used):
        useful_diff_trail = find_useful_diff_trail(round_num, most_probable_differential_trails, sboxes_already_used)
        print('Found useful differential trail: ' + get_string_1d_hex(useful_diff_trail[1]) + ' -> ' + get_string_1d_hex(useful_diff_trail[2]))
        print('\tBreaking key bits...')

        input_xor = useful_diff_trail[1]
        most_probable_output_xor = useful_diff_trail[2]

        breaking_key_bits = find_which_key_bits_will_be_broken(round_num, most_probable_output_xor)
        broken_key_bits = break_key_bits(round_num, input_xor, most_probable_output_xor, breaking_key_bits, round_keys)

        print('\tFound key bits ' + get_string_1d_hex(combine_bits_into_nibbles(broken_key_bits)))

        # Set the keybits which were broken
        for i in range(len(breaking_key_bits)):
            if breaking_key_bits[i] == 1:
                round_key[i] = broken_key_bits[i]

        # Mark which sboxes this used up
        for i in range(4):
            if most_probable_output_xor[i] != 0:
                sboxes_already_used[i] = True

    # We want it as list of nibbles at the end
    round_key = combine_bits_into_nibbles(round_key)

    print('*************************************')
    print('  Found KEY' + str(round_num + 1) + ' = ' + get_string_1d_hex(round_key))
    print('*************************************')

    return round_key

def break_key_bits(round_num, input_xor, output_xor, breaking_key_bits, round_keys):
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
        guess_key_bits(round_num, text1, text2, output_xor, key_count_dict, breaking_key_bits, round_keys)

    # Extract the most likely key out of the dictonary
    most_probable_key = sorted(key_count_dict.items(), key=lambda x: x[1], reverse=True)[0][0]

    # Put key back into list form, since it was a string in the dict
    final_key_guess = list(map(int, most_probable_key.split(' ')))

    # We want it as array of bits, not nibbles
    final_key_guess = split_nibbles_into_bits(final_key_guess)

    return final_key_guess

def guess_key_bits(round_num, ciphertext1, ciphertext2, output_xor, key_count_dict, breaking_key_bits, round_keys):
    total_needed_key_guesses = 1

    for bit in breaking_key_bits:
        if bit == 1:
            total_needed_key_guesses *= 2

    for i in range(total_needed_key_guesses):
        key_guess_bits = [0] * 16
        div = total_needed_key_guesses / 2

        # This for loop is hard to understand but it loops thorough all possible
        # keys only for the bits where breaking_key_bits is set
        for j in range(len(breaking_key_bits)):
            if breaking_key_bits[j] == 1:
                if i > div - 1 and i % (div * 2) >= div:
                    key_guess_bits[j] = 1

                div /= 2

        key_guess = combine_bits_into_nibbles(key_guess_bits)
        key_as_string = ' '.join(map(str, key_guess))

        round_keys[round_num + 1] = key_guess

        partial_xor = partial_decryption(round_num, ciphertext1, ciphertext2, round_keys)

        if partial_xor == output_xor:
            if key_as_string not in key_count_dict:
                key_count_dict[key_as_string] = 1
            else:
                key_count_dict[key_as_string] += 1

def partial_decryption(round_num, ciphertext1, ciphertext2, round_keys):
    if round_num <= 3:
        partially_decrypted1 = xor(ciphertext1, round_keys[4])
        partially_decrypted2 = xor(ciphertext2, round_keys[4])

        inv_substitute(partially_decrypted1)
        inv_substitute(partially_decrypted2)
    if round_num <= 2:
        partially_decrypted1 = xor(partially_decrypted1, round_keys[3])
        partially_decrypted2 = xor(partially_decrypted2, round_keys[3])

        inv_permutate(partially_decrypted1)
        inv_permutate(partially_decrypted2)

        inv_substitute(partially_decrypted1)
        inv_substitute(partially_decrypted2)
    if round_num <= 1:
        partially_decrypted1 = xor(partially_decrypted1, round_keys[2])
        partially_decrypted2 = xor(partially_decrypted2, round_keys[2])

        inv_permutate(partially_decrypted1)
        inv_permutate(partially_decrypted2)

        inv_substitute(partially_decrypted1)
        inv_substitute(partially_decrypted2)
    if round_num <= 0:
        partially_decrypted1 = xor(partially_decrypted1, round_keys[1])
        partially_decrypted2 = xor(partially_decrypted2, round_keys[1])

        inv_permutate(partially_decrypted1)
        inv_permutate(partially_decrypted2)

        inv_substitute(partially_decrypted1)
        inv_substitute(partially_decrypted2)

    return xor(partially_decrypted1, partially_decrypted2)

def break_first_round_key(round_keys):
    # Encrypt random plaintext
    plaintext = choose_random_plaintext()
    ciphertext = plaintext.copy()
    encrypt(ciphertext)

    # Decrypt ciphertext all the way to last xor with the round_keys we found
    add_round_key(ciphertext, round_keys[4])
    inv_substitute(ciphertext)

    add_round_key(ciphertext, round_keys[3])
    inv_permutate(ciphertext)
    inv_substitute(ciphertext)

    add_round_key(ciphertext, round_keys[2])
    inv_permutate(ciphertext)
    inv_substitute(ciphertext)

    add_round_key(ciphertext, round_keys[1])
    inv_permutate(ciphertext)
    inv_substitute(ciphertext)

    # Get the last key
    return xor(plaintext, ciphertext)

def find_which_key_bits_will_be_broken(round_num, most_probable_output_xor):
    breaking_key_bits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    for i in range(len(most_probable_output_xor)):
        if most_probable_output_xor[i] != 0:
            breaking_key_bits[i * 4] = 1
            breaking_key_bits[i * 4 + 1] = 1
            breaking_key_bits[i * 4 + 2] = 1
            breaking_key_bits[i * 4 + 3] = 1

    if round_num < 3: # If round_num < 3 we need to take the permutation into account
        tmp = breaking_key_bits.copy()

        for i in range(len(breaking_key_bits)):
            breaking_key_bits[i] = tmp[INV_PBOX[i]]
        
    return breaking_key_bits

def find_useful_diff_trail(round_num, most_probable_differential_trails, sboxes_already_used):
    for diff_trail in most_probable_differential_trails:
        most_probable_output_xor = diff_trail[2]

        # Check if this diff_trail will use any sboxes which we haven't used already
        for i in range(4):
            if most_probable_output_xor[i] != 0 and sboxes_already_used[i] == False: # Hit! We can use this one
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

    num_final_active_sboxes = 0

    for nibble in current_xor:
        if nibble > 0: num_final_active_sboxes += 1

    # Give lower probability if there's a lot of active sboxes at the end
    # The more active sboxes, the more key bits we'll have to break at a time
    # For 2 active sboxes the key bits are broken within a couple of seconds so don't have to mess with the probability
    # 3 active sboxes will could take ~10 sec
    # 4 active sboxes will take a very long time so we never want to use them. Try to find alternatives with less active sboxes
    if num_final_active_sboxes == 3: probability /= 4
    if num_final_active_sboxes == 4: probability = 0

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

""" END OF DIFFERENTIAL CRYPTANALYSIS OF SPN """



""" START OF SPN CIPHER """

def encrypt(state):
    add_round_key(state, KEY0)
    substitute(state)
    permutate(state)

    add_round_key(state, KEY1)
    substitute(state)
    permutate(state)

    add_round_key(state, KEY2)
    substitute(state)
    permutate(state)

    add_round_key(state, KEY3)
    substitute(state)

    add_round_key(state, KEY4)

def decrypt(state):
    add_round_key(state, KEY4)

    inv_substitute(state)
    add_round_key(state, KEY3)

    inv_permutate(state)
    inv_substitute(state)
    add_round_key(state, KEY2)

    inv_permutate(state)
    inv_substitute(state)
    add_round_key(state, KEY1)

    inv_permutate(state)
    inv_substitute(state)
    add_round_key(state, KEY0)

def substitute(state):
    # state = array of nibbles, not bytes
    for i in range(len(state)):
        state[i] = SBOX[state[i]]

def permutate(state):
    # state = array of nibbles, not bytes
    new_state_as_bits = [0] * 16
    state_as_bits = split_nibbles_into_bits(state)

    for i in range(len(state_as_bits)):
        new_state_as_bits[PBOX[i]] = state_as_bits[i]

    state[:] = combine_bits_into_nibbles(new_state_as_bits)

def inv_substitute(state):
    # state = array of nibbles, not bytes
    for i in range(len(state)):
        state[i] = INV_SBOX[state[i]]

def inv_permutate(state):
    # state = array of nibbles, not bytes
    new_state_as_bits = [0] * 16
    state_as_bits = split_nibbles_into_bits(state)

    for i in range(len(state_as_bits)):
        new_state_as_bits[INV_PBOX[i]] = state_as_bits[i]

    state[:] = combine_bits_into_nibbles(new_state_as_bits)

def add_round_key(state, key):
    # state, key = array of nibbles, not bytes

    for i in range(len(key)):
        state[i] = state[i] ^ key[i]

def xor(p1, p2):
    xor = []

    for i in range(len(p1)):
        xor.append(p1[i] ^ p2[i])

    return xor

""" END OF SPN CIPHER """



""" START OF HELPER FUNCTIONS """

def split_nibbles_into_bits(nibble_array):
    bit_array = []

    for nibble in nibble_array:
        bit_array.append((nibble >> 3) & 1)
        bit_array.append((nibble >> 2) & 1)
        bit_array.append((nibble >> 1) & 1)
        bit_array.append(nibble & 1)

    return bit_array

def combine_bits_into_nibbles(bits_array):
    nibble_array = []

    for i in range(0, len(bits_array), 4):
        nibble = bits_array[i] << 3 | bits_array[i + 1] << 2 | bits_array[i + 2] << 1 | bits_array[i + 3]
        nibble_array.append(nibble)

    return nibble_array

# Normal printing is going to print integers in decimal. For debugging, hex is much easier
def print_1d_hex(arr):
    print(get_string_1d_hex(arr))

# Normal printing is going to print integers in decimal. For debugging, hex is much easier
def print_2d_hex(arr):
    print(get_string_2d_hex(arr))

def get_string_2d_hex(arr):
    string = '[\n'

    for i in range(len(arr)):
        string += '  ['
        for j in range(len(arr[i])):
            string += '{:#02x}'.format(arr[i][j]) + ', '

        string = string[:-2] # remove the ', ' from last element
        string += ']\n'

    string += ']'

    return string

def get_string_1d_hex(arr):
    string = '['

    for i in range(len(arr)):
        string += '{:#02x}'.format(arr[i]) + ', '

    string = string[:-2] # remove the ', ' from last element
    string += ']'

    return string

""" END OF HELPER FUNCTIONS """
    
if __name__=="__main__":
    main()
