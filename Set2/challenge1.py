import base64
key = 'YELLOW SUBMARINE'
key_length=len(key.encode('utf-8'))
length_total = int(input("Enter the length in bytes you want data to be\n"))
final_byte_array = bytearray(key.encode('utf-8'))
pad_number = length_total - len(final_byte_array)
while len(final_byte_array) < length_total:
    final_byte_array.append(pad_number)

print(bytes(final_byte_array))