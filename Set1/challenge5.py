import binascii

lyrics = "Hello the key for this cipher was my name, did you get it correct?".encode("utf-8")


key ="LIAM".encode('utf-8')

result = bytearray()

rotating = 0
for byte in lyrics:
    result.append(byte^key[rotating])
    if rotating == len(key)-1:
        rotating = 0
    else:
        rotating+=1
        
print(result.hex())
        