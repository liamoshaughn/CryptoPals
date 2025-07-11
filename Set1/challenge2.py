import base64
str = '1c0111001f010100061a024b53535009181c'
key ='686974207468652062756c6c277320657965'


print(bytes(a ^ b for a, b in zip(bytes.fromhex(str), bytes.fromhex(key))).hex())