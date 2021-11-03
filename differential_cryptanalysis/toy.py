# This a simple "toy" cipher. Taken from http://theamazingking.com/crypto-diff.php

SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
#SBOX = [0x3, 0xe, 0x1, 0xa, 0x4, 0x9, 0x5, 0x6, 0x8, 0xb, 0xf, 0x2, 0xd, 0xc, 0x0, 0x7]

KEY1 = 0x7
KEY2 = 0xe

def main():
    #for state in range(16):
    #    encrypted_state = encrypt(state)
    #    print(str(state) + " -> " + str(encrypted_state))

    diff_dist_table = build_difference_distribution_table(SBOX)
    sorted_differentials = get_most_probable_differentials(build_difference_distribution_table(SBOX))
    good_pair = get_good_pair(sorted_differentials)
    keys = break_keys(good_pair, diff_dist_table)

    print(keys)

def break_keys(good_pair, diff_dist_table):
    plain0 = good_pair[0]
    plain1 = good_pair[1]
    
    cipher0 = encrypt(good_pair[0])
    cipher1 = encrypt(good_pair[1])

    input_differential = plain0 ^ plain1
    output_differential = cipher0 ^ cipher1

    diff_dist_entry = diff_dist_table[input_differential][output_differential]

    for entry in diff_dist_entry:
        key0_guess = plain0 ^ entry[0]
        key1_guess = cipher0 ^ entry[2]

        if confirm_key_guess(key0_guess, key1_guess):
            return (key0_guess, key1_guess)

def confirm_key_guess(key0_guess, key1_guess):
    for i in range(16):
        if encrypt(i) != encrypt_with_keys(i, key0_guess, key1_guess):
            return False

    return True


def get_good_pair(sorted_differentials):
    for differential in sorted_differentials:
        for plain0 in range(16): # Chosing plain0 at "random"
            plain1 = plain0 ^ differential[0]

            cipher0 = encrypt(plain0)
            cipher1 = encrypt(plain1)

            if cipher0 ^ cipher1 == differential[1]: # GOOD PAIR!
                return (plain0, plain1)

def get_most_probable_differentials(diff_dist_table): # sort by propagation ratio
    sorted_differentials = []

    for i in range(len(diff_dist_table) * len(diff_dist_table[0])):
        max = -1
        input_differential = 0
        output_differential = 0

        for j in range(len(diff_dist_table)):
            for k in range(len(diff_dist_table[j])):
                differential_count = len(diff_dist_table[j][k])

                if (differential_count > max and differential_count > 0 and differential_count < 16): # diff_dist_table[0][0] will always be = 16. We ignore that one and anything <= 0
                    max = differential_count
                    input_differential = j
                    output_differential = k

        if input_differential != 0 and output_differential != 0:
            diff_dist_table[input_differential][output_differential] = []
            sorted_differentials.append((input_differential, output_differential))

    return sorted_differentials

def build_difference_distribution_table(sbox):
    diff_dist_table = [[[] for i in range(16)] for j in range(16)]

    for x_prime in range(16):
        for x in range(16):
            x_star = x ^ x_prime

            y = sbox[x]
            y_star = sbox[x_star]
            y_prime = y ^ y_star

            diff_dist_table[x_prime][y_prime].append((x, x_star, y, y_star))

    return diff_dist_table


""" Toy Cipher """

def encrypt(state):
    state = add_round_key(state, KEY1)
    state = sub(state)
    state = add_round_key(state, KEY2)

    return state

def encrypt_with_keys(state, key1, key2): # function useful for testing keys
    state = add_round_key(state, key1)
    state = sub(state)
    state = add_round_key(state, key2)

    return state

def sub(state):
    return SBOX[state]

def add_round_key(state, key):
    return state ^ key

if __name__=="__main__":
    main()
