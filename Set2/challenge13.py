# In challenge13.py
from Helpers import AES_ECB

import secrets
import base64
from Crypto.Util.Padding import pad


def parse_kv(cookie_string):
    user_object = {pair.split("=")[0]: pair.split("=")[1] for pair in cookie_string.split('&')}
    return user_object

def profile_for(text, key):
    secure_string = text.replace("=", "_").replace("&", "_")
    
    user_object = {
        'email' : secure_string,
        'uid' : 10,
        'role' :  'user'
    }
    
    cookie_string = "email=" + user_object['email'] + "&uid="+str(user_object['uid']) + "&role=" + user_object['role']
        # decrypted = AES_ECB.decrypt(encrypted,key)
    # profile = parse_kv(decrypted)
    return AES_ECB.encrypt(cookie_string, key)
    

def main():
    
    key = secrets.token_hex(16)
    
    #Create cipher text for just 26 padding, 26 because "email=" + 10 empty bytes + 16 bytes will create a cipher block of just empty bytes that we can append to the end of our cipher text. We do this because AES expects padding at the end of a cipher text
    text = (pad(b"", 10) + pad(b"",16)).decode('utf-8')
    encrypted = profile_for(text, key)
    encrypted = bytes.fromhex(base64.b64decode(encrypted).decode('utf-8'))
    chunks = [encrypted[i:i + 16] for i in range(0, len(encrypted), 16)]
    padding = chunks[1].hex()
    
    #We now need to create a block that just says admin + 11 empty bytes
    text = (pad(b"", 10) + pad(b"admin", 16)).decode('utf-8')
    encrypted = profile_for(text, key)
    encrypted = bytes.fromhex(base64.b64decode(encrypted).decode('utf-8'))
    chunks = [encrypted[i:i + 16] for i in range(0, len(encrypted), 16)]
    admin_block = chunks[1].hex()
    
    #Here we have to make sure our input is the correct length so that the end of one of the blocks is role=admin, we then combine that block with our admin block and padding block to create a new cipher text that we can decode
    text = "hel@gmail.com"
    encrypted = profile_for(text, key)
    encrypted = bytes.fromhex(base64.b64decode(encrypted).decode('utf-8'))
    b64string = base64.b64encode((encrypted[:-16].hex() + admin_block + padding).encode('utf-8')).decode('utf-8')
    decrypted = AES_ECB.decrypt(b64string,key)
    
    #remove padding from the end of our decrypted string
    decrypted = decrypted.encode('utf-8')[:-decrypted.encode('utf-8')[-1]].decode('utf-8')
    
    profile = parse_kv(decrypted)
    print(profile)
    
    
    



if __name__ == "__main__":
    main()