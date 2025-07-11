import base64

#Calculate the hemming distance between two strings in bytes
def hamming_distance(s1, s2):  
    return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(s1, s2))

#Solve a single byte xor cipher
def single_byte_xor(ciphertext, key):
    return bytes([b ^ key for b in ciphertext])


#Score a plaintext based on how many english letters are in the text
def score_plaintext(text):
    freq = {
        'a': 0.082, 'b': 0.015, 'c': 0.028, 'd': 0.043,
        'e': 0.127, 'f': 0.022, 'g': 0.020, 'h': 0.061,
        'i': 0.070, 'j': 0.002, 'k': 0.008, 'l': 0.040,
        'm': 0.024, 'n': 0.067, 'o': 0.075, 'p': 0.019,
        'q': 0.001, 'r': 0.059, 's': 0.063, 't': 0.090,
        'u': 0.028, 'v': 0.010, 'w': 0.024, 'x': 0.002,
        'y': 0.020, 'z': 0.00074, ' ': 0.240
    }
    score = 0
    for char in text.lower():   
        if chr(char) in freq:         
            score += 0.1
        elif 0 <= char < 32 or char > 127:  # Non-printable ASCII
            score -= 0.1
    return score


#Break a single byte XOR by using multiple single byte keys and scoring
def break_single_byte_xor(ciphertext):
    best_score = -1
    best_key = None
    best_plaintext = None
    
    for key in range(256):
        plaintext = single_byte_xor(ciphertext, key)
        current_score = score_plaintext(plaintext)

        if current_score > best_score:
            best_score = current_score
            best_key = key
            best_plaintext = plaintext
    
    return best_key, best_plaintext


#Solve a rotating xor cipher with a known key
def solve_rotating_xor_cipher(cipher_decoded, key):
    rotating_count = 0
    decoded_message = ""
    

    for byte in cipher_decoded:
        decoded_message += chr(byte^ord(key[rotating_count]))
        if rotating_count < len(key)-1:
            rotating_count += 1
        else:
            rotating_count = 0
    return decoded_message


cipher = ''

with open('6.txt') as my_file:
    cipher += my_file.read()

cipher = base64.b64decode(cipher)

key_size = 2

distance_results = [99, 99]


#Find the key size of a key by calculating the average distance over multiple key size blocks
while key_size <= 40:
    chunks = [cipher[i*key_size : (i+1)*key_size] for i in range(4)]
    avg_dist = sum(
        hamming_distance(chunks[i], chunks[j]) / key_size
        for i, j in [(0,1), (0,2), (1,2), (0,3), (1,3), (2,3)]
    ) / 6
    distance_results.append(avg_dist)
    key_size += 1

#take the smallest key and break cipher into key-size chunks, transpose so we can solve each byte as a single byte XOR cipher
smallest = distance_results.index(min(distance_results))

chunks = [cipher[i:i+smallest] for i in range(0, len(cipher), smallest)]

transposed_chunks = [bytearray() for _ in range(smallest)]

for chunk in chunks:
    for i in range(len(chunk)):
        transposed_chunks[i].append(chunk[i])

key_string = ""

#break each transposed chunks key
for chunk in transposed_chunks:
    key, plaintext = break_single_byte_xor(chunk)

    key_string += chr(key)

#Now that we know the key we can solve the whole cipher
print(solve_rotating_xor_cipher(cipher, key_string))



