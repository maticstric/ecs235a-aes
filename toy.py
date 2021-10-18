# This a simple "toy" cipher. Taken from http://theamazingking.com/crypto-diff.php

SBOX = [0xe, 0x2, 0xb, 0x0, 0x4, 0x6, 0x7, 0xf, 0x8, 0x5, 0x3, 0x9, 0xd, 0xc, 0x1, 0xa]

KEY1 = 0xa
KEY2 = 0x4

def main():
    #for state in range(16):
    #    encrypted_state = encrypt(state)
    #    print(str(state) + " -> " + str(encrypted_state))

    diff_dist_table = build_difference_distribution_table()

    for row in diff_dist_table:
        print(row)

def build_difference_distribution_table():
    diff_dist_table = [[0 for i in range(16)] for j in range(16)]

    for x in range(16):
        for x_star in range(16):
            x_prime = x ^ x_star

            y = SBOX[x]
            y_star = SBOX[x_star]
            y_prime = y ^ y_star

            diff_dist_table[x_prime][y_prime] += 1

    return diff_dist_table


""" Toy Cipher """

def encrypt(state):
    state = add_round_key(state, KEY1)
    state = sub(state)
    state = add_round_key(state, KEY2)

    return state

def sub(state):
    return SBOX[state]

def add_round_key(state, key):
    return state ^ key

if __name__=="__main__":
    main()
