from PIL import Image 
import aes
import encrypt_aes

# Citation: Some of this work was outlined by Philip Wang, 
# at https://www.quora.com/How-do-I-encrypt-and-decrypt-an-image-file-using-ECB-CBC-AES-encryption-or-something-like-this-in-python-using-a-program

filename = '../images/davis.png' 
filename_out_ecb = '../images/davis_encrypted_ecb.png' 
filename_out_cbc = '../images/davis_encrypted_cbc.png' 

# Maps the RGB  
def convert_to_RGB(data): 
    r, g, b = tuple(map(lambda d: [data[i] for i in range(0, len(data)) if i % 3 == d], [0, 1, 2])) 
    pixels = tuple(zip(r, g, b)) 

    return pixels 

def process_image(filename): 
    # Opens image and converts it to RGB format for PIL 
    image = Image.open(filename) 
    data = image.convert('RGB').tobytes()

    original_len = len(data)

    keys = aes.key_expansion(aes.KEY)
    aes.pad_message_array(data)

    # Encrypt with ecb mode
    data_blocks = aes.split_message_array_into_blocks(data)
    encrypt_aes.encrypt_message_ecb(data_blocks, keys)
    encrypted_data = aes.combine_blocks_into_message_array(data_blocks)[:original_len]

    # Create a new PIL Image object and save the old image data into the new image. 
    ecb_rgb = convert_to_RGB(encrypted_data)
    ecb_image = Image.new(image.mode, image.size)
    ecb_image.putdata(ecb_rgb) 
    ecb_image.save(filename_out_ecb, 'png') 


    # Encrypt with cbc mode
    data_blocks = aes.split_message_array_into_blocks(data)
    encrypt_aes.encrypt_message_cbc(data_blocks, keys, aes.IV)
    encrypted_data = aes.combine_blocks_into_message_array(data_blocks)[:original_len]

    # Create a new PIL Image object and save the old image data into the new image. 
    cbc_rgb = convert_to_RGB(encrypted_data)
    cbc_image = Image.new(image.mode, image.size)
    cbc_image.putdata(cbc_rgb) 
    cbc_image.save(filename_out_cbc, 'png') 

process_image(filename)
