import base64

def main():
    key = 'YELLOW SUBMARINE'
    length_total = int(input("Enter the length in bytes you want data to be\n"))
    final_byte_array = bytearray(key.encode('utf-8'))
    pad_number = length_total - len(final_byte_array)
    while len(final_byte_array) < length_total:
        final_byte_array.append(pad_number)

    print(bytes(final_byte_array))

if __name__ == "__main__":
    main()