import binascii

def single_byte_xor(ciphertext, key):
    return bytes([b ^ key for b in ciphertext])

def score_plaintext(text):
    # Common English letters (including space)
    freq = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
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
    
    return best_key, best_plaintext


def main():
    # Given ciphertext
    ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    # Break the cipher
    key, plaintext = break_single_byte_xor(ciphertext_hex)

    print(f"Key: {key} (ASCII: {chr(key)})")
    print(f"Plaintext: {plaintext.decode('ascii')}")

if __name__ == "__main__":
    main()