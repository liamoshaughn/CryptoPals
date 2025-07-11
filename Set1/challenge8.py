from Crypto.Cipher.AES import block_size

def main():
    with open('8.txt') as my_file:
        for line in my_file:
            byte_string = bytes.fromhex(line.replace('\n', ''))
            chunks = [byte_string[i:i + block_size] for i in range(0, len(byte_string), block_size)]
            number_of_duplicates = len(chunks) - len(set(chunks))
            if number_of_duplicates > 0:
                print(line)



if __name__ == "__main__":
    main()