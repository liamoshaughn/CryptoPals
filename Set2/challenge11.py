from Crypto.Util.Padding import pad
from Crypto.Cipher.AES import block_size
import base64
import secrets


s_box = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

rounds = 11

def gf_mult(a, b):
# Galois Field multiplication in GF(2^8)
    p = 0
    for _ in range(8):
        if b & 1 == 1:
            p ^= a
        carry = a & 0x80
        a <<= 1 & 0xFF
        if carry == 0x80:
            a ^= 0x11B
        b >>= 1
    return p

#Turns a hex string of data into column order state matrix
def hex_to_state(hex_str):
    #Converts a 32-character hex string to a 4x4 AES state matrix (hex strings).
 
    assert len(hex_str) == 32, "Hex string must be 32 chars (16 bytes)"
    return [
        [hex_str[8*j + 2*i : 8*j + 2*i + 2] for j in range(4)
    ] for i in range(4)]

def state_to_hex(state_matrix):
    #Converts a 4x4 AES state matrix back to a 32-character hex string.
    hex_str = ''
    # Reconstruct column by column
    for j in range(4):  # columns
        for i in range(4):  # rows
            # Get hex value, remove '0x' prefix, and ensure 2 digits
            hex_byte = state_matrix[i][j][2:]  # Remove '0x'
            hex_byte = hex_byte.zfill(2)  # Ensure 2 digits
            hex_str += hex_byte
    return hex_str

def shift_rows(state_matrix):
    for i in range(4):
        #shift rows to the left
        state_matrix[i] = state_matrix[i][i:] + state_matrix[i][:i]
    
    return(state_matrix)

def mix_columns(state_matrix):
    inv_const_matrix = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
    ] 
    #Calculate a number using a polynomial formula with the variables being the above matrix and column first of the state matrix
    for i in range(4):
        result = [0,0,0,0]
        for j in range(4):
            result[j] = hex(gf_mult(inv_const_matrix[j][0],int(state_matrix[0][i],16)) ^ gf_mult(inv_const_matrix[j][1],int(state_matrix[1][i],16)) ^ gf_mult(inv_const_matrix[j][2],int(state_matrix[2][i],16)) ^ gf_mult(inv_const_matrix[j][3],int(state_matrix[3][i],16)))
        state_matrix[0][i] = result[0]
        state_matrix[1][i] = result[1]
        state_matrix[2][i] = result[2]
        state_matrix[3][i] = result[3]
    
    return state_matrix
    
def sub_bytes(state_matrix):
    for i in range(len(state_matrix)):
        for j in range(4):
            #split into nibbles so we can search s_box
            hex_part = state_matrix[i][j][2:].zfill(2)
            a, b = int(hex_part[0],16), int(hex_part[1],16) 
            state_matrix[i][j] = hex(s_box[a][b])
    
    return state_matrix
    
def add_round_key(key, state_matrix):
    #xor round key with state_matrix
    key_matrix = hex_to_state(key)
    
    for i in range(len(state_matrix)):
        for j in range(len(state_matrix[i])):
            state_matrix[i][j] = hex((int(state_matrix[i][j], 16) ^ int(key_matrix[i][j],16)))
    
    return state_matrix

def expand_key(key):
    
    keys = [0] * rounds
    round_constant = [0,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36] 
    keys[0] = key.hex()
    for i in range(rounds):
        if i == 0:
            continue
        #split key into chunks so we can get the last 4 bytes
        chunks = [keys[i-1][j:j + 8] for j in range(0, len(keys[i-1]), 8)]

        #rotate last 4 bytes 1 byte
        rotated_chunk = chunks[3][2:] + chunks[3][:2]
        
        #Turn bytes into nibbles so we can then do a s_box lookup
        rotated_chunk = [rotated_chunk[j:j + 2] for j in range(0, len(rotated_chunk), 2)]
        rotated_chunk = [s_box[int(byte[0], 16)][int(byte[1], 16)] for byte in rotated_chunk]
        
        #Add round constant and add to the front of new key
        rotated_chunk[0] = rotated_chunk[0] ^ round_constant[i]
        
        rotated_chunk = bytes(rotated_chunk).hex()
        new_key = [bytes(a ^ b for a, b in zip(bytes.fromhex(rotated_chunk), bytes.fromhex(chunks[0]))).hex()]
        
        #Cycle through using our new chunk with previous key chunks to create new key
        for j in range(3):
            new_key.append(bytes(a ^ b for a, b in zip(bytes.fromhex(new_key[j]), bytes.fromhex(chunks[j+1]))).hex())
        
        keys[i] = ''.join(new_key)
        
    return keys

def xor_strings(current, previous):
    return bytes(a ^ b for a, b in zip(bytes.fromhex(current), bytes.fromhex(previous))).hex()
    

def encryption_oracle(user_input):
    key = secrets.token_hex(8).encode('utf-8')
    mode = secrets.randbelow(2)
    # print('CBC' if mode else 'ecb')    

    #Challenge Asks to bad so PAD I SHALL
    before = secrets.randbelow(6) + 5
    after = secrets.randbelow(6) + 5
    
    user_input = pad(b'', before) + user_input + pad(b'', after)
    
    #Ensure Correct Block Size
    if len(user_input)%16 > 0:
        user_input = pad(user_input, len(user_input)+(16 - len(user_input)%16))
    else:
        user_input = pad(user_input, len(user_input)+16)
    
    chunks = [user_input[i:i + 16] for i in range(0, len(user_input), 16)]
    
    keys = expand_key(key)
    encrypted = ''
    
    #I'm just gonna call this iv but will be used to store the previous cipher block
    iv = secrets.token_hex(16)
    
    for chunk in chunks:
        
        state_matrix = []
        #For CBC we have to XOR from previous Cipher
        if mode:
            chunk = xor_strings(chunk.hex(), iv)
            state_matrix = hex_to_state(chunk)
        else:
            state_matrix =  hex_to_state(chunk.hex())

        #Every round but round 0 
        state_matrix = add_round_key(keys[0], state_matrix)
        for round in range(1,rounds, 1):
            state_matrix = sub_bytes(state_matrix)
            
            state_matrix =  shift_rows(state_matrix)
            
            if round != 10:
                state_matrix =  mix_columns(state_matrix) 
            
            state_matrix = add_round_key(keys[round], state_matrix)
    
        iv = state_to_hex(state_matrix)
       
        encrypted += iv


    return encrypted
    
    

def main():
    #The difference between ECB AND CBC is that CBC provides diffusion between blocks of cipher text, ECB does not. #This means that to detect if our algo is using ECB or CBC we feed into our generator repeated text. 
    #In CBC we should not see any repeated cipher but in ECB because it does not diffuse between chunks all repeated chunks will produce the same cipher text allowing us to tell which method was chosen.
    repeated_text = b"BangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarangBangarang"
    
    #20 Bangarang's seemed to be enough to detect repeated blocks through 10-20 extra padding bytes but I doubled it just to be safe
    
    cipher = encryption_oracle(repeated_text)
    
    chunks = [cipher[i:i + block_size] for i in range(0, len(cipher), block_size)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    
    print(f"This round the text seemed to be encrypted by {'CBC' if number_of_duplicates == 0 else 'ECB'}")
    

if __name__ == "__main__":
    main()