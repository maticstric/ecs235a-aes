# ECS 235A — AES and Differential Cryptanalysis
This repo contains all the code for the ECS 235A (fall 2021) quarter-long project on AES and differential cryptanalyasis.

# How to Run the Code
Note that Python 3 is required.

For the sake of simplicity, none of the scripts take command line arguments. Instead, you can directly change the variables in the code (they all have default values so you can keep them as they are). This README specifies which variables you can edit (they are also marked in each individual file). Since this was purely an educational exercise, we don't check that the variables that you change will be of the correct type/length/format. Please be nice to the scripts (we are well aware of the irony of saying this while taking a security class).

There are three major parts to the code:
1. AES implementation
2. Breaking a toy cipher with differential cryptanalysis
3. Breaking an SPN with differential cryptanalysis

## AES
All of the AES code can be found in the [./aes](aes) directory. The directory contains four files:

1. `aes.py`

    This is the file with the `main` function and should be run to test our implementation (`python3 aes.py`). There are no command line arguments. Instead, you can feel free to edit the following variables in the file directly:
    1. `KEY` — array of bytes (of length 16, 24, or 32): the key that AES will use. Some example keys (taken from official FIPS documentation) of length 128, 192, and 256 bits are commented out if you want to use them. Note that the `KEY_LENGTH` and `NUM_OF_ROUNDS` are automatically calculated from the length of the `KEY` array you give
    2. `IV` — 4 x 4 array of bytes: the IV for CBC mode
    3. `MESSAGE_ARRAY` — array of bytes (of any length): the actual message to encrypt

    Look into the main function to see what the script does. It should be very straightforward. It pads the message array, runs the key schedule, splits the message array into 128 bit blocks, and then encrypts and decrypts the blocks. Currently ECB mode is used but you can replace the encryption function with `encrypt_message_cbc` and add the IV as an argument if you want to try CBC mode (don't forget to also change the decryption function being used).

2. `decrypt_aes.py`

    This includes all the decryption functions for AES. It has no main function and shouldn't be run.

3. `encrypt_aes.py`

    This includes all the encryption functions for AES. It has no main function and shouldn't be run.

4. `encrypt_images.py`

    Used to encrypt the UC Davis seal with both ECB and CBC mode to show their difference. The resulting images are used in our paper.

## Toy Cipher
All of the toy cipher code can be found in the [differential_cryptanalysis/toy.py](./differential_cryptanalysis/toy.py) file:

1. `toy.py`

    To run this simply run `python3 toy.py`. The `main` function will run the differential cryptanalysis steps outlined in the paper and print out the broken keys. Because this is such a simple cipher, this happens almost instantly.

    There are no command line arguments. Instead, you can feel free to edit the following variables in the file directly:
    1. `SBOX` — array of nibbles (of length 16): the SBOX for the cipher
    2. `KEY0` — nibble: the first round key
    3. `KEY1` — nibble: the second round key

## SPN
All of the SPN code can be found in the [differential_cryptanalysis/spn.py](./differential_cryptanalysis/spn.py) file:

1. `spn.py`

    To run this simply run `python3 spn.py`. The `main` function will run the step outlined in the paper and print out the broken keys. It takes ~2 min to break them, though it might be more or less depending on the machine.

    There are no command line arguments. Instead, you can feel free to edit the following variables in the file directly:
    1. `SBOX` & `INV_SBOX` — array of nibbles (of length 16): the SBOX and INV_SBOX for the cipher. Make sure `INV_SBOX` is actually the inverse of `SBOX` if you make manual changes
    2. `PBOX` & `INV_PBOX` — array of nibbles (of length 16): the PBOX and INV_PBOX for the cipher. Make sure `INV_PBOX` is actually the inverse of `PBOX` if you make manual changes
    3. `KEY0` — array of nibbles (of length 4): the first round key
    4. `KEY1` — array of nibbles (of length 4): the second round key
    5. `KEY2` — array of nibbles (of length 4): the third round key
    6. `KEY3` — array of nibbles (of length 4): the fourth round key
    7. `KEY4` — array of nibbles (of length 4): the fifth round key
    8. `NUM_CHOSEN_PLAINTEXTS` — int: the number of chosen plaintexts used to break key bits. Look at the paper for more information on this variable

    Some commented out SBOXes, PBOXes, and KEYs are there if you want to test something different. Of course, you can also create your own, just make them the right size.

    If you run this and the keys aren't being broken correctly, you might have to increase `NUM_CHOSEN_PLAINTEXTS` (the higher the number, the slower the program, but the higher the accuracy). We found 1000 to be enough, but differential cryptanalysis works probabilistically, so there's always a chance that it guesses the keys incorrectly, especially if you design the SBOX and PBOX particularly well.
