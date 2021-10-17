# This a simple "toy" cipher. Taken from http://theamazingking.com/crypto-diff.php
                                                                                   
SBOX = [0xe, 0x2, 0xb, 0x0, 0x4, 0x6, 0x7, 0xf, 0x8, 0x5, 0x3, 0x9, 0xd, 0xc, 0x1, 0xa]
                                                                                   
def main():                                                                        
    key1 = 0xa                                                                     
    key2 = 0x4                                                                     
                                                                                   
    for state in range(16):                                                        
        encrypted_state = encrypt(state, key1, key2)                               
        print(str(state) + " -> " + str(encrypted_state))                          
                                                                                   
def encrypt(state, key1, key2):                                                    
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
