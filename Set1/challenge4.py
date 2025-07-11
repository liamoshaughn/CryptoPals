import binascii

def single_byte_xor(ciphertext, key):
    return bytes([b ^ key for b in ciphertext])

def score_plaintext(text):
    # Frequency of common English letters (including space)
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

def break_single_byte_xor(ciphertext_hex):
    ciphertext = bytes.fromhex(ciphertext_hex)
    best_score = -1
    best_key = None
    best_plaintext = None
    
    for key in range(256):  # Try all possible single-byte keys
        plaintext = single_byte_xor(ciphertext, key)
        current_score = score_plaintext(plaintext)

        if current_score > best_score:
            best_score = current_score
            best_key = key
            best_plaintext = plaintext
    
    return best_key, best_plaintext, best_score

def main():
    #open file and put into array
    cipher_array = []
    with open('4.txt') as my_file:
        for line in my_file:
            cipher_array.append(line)

    # Break the cipher

    best_score = -1
    best_key = None
    best_plaintext = None
    for cipher in cipher_array:
        key, plaintext, score = break_single_byte_xor(cipher)
        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext
            
        
    print(f"Key: {best_key} (ASCII: {chr(best_key)})")
    print(f"Plaintext: {best_plaintext.decode('ascii')}")

if __name__ == "__main__":
    main()