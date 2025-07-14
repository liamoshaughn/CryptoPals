# In challenge13.py
from Helpers import AES_ECB

import secrets


def parse_kv(cookie_string):
    user_object = {pair.split("=")[0]: pair.split("=")[1] for pair in cookie_string.split('&')}
    print(user_object)
    return user_object

def profile_for(text):
    secure_string = text.split('=')[0]
    secure_string = secure_string.split('&')[0]
    
    user_object = {
        'email' : secure_string,
        'uid' : secrets.randbelow(10000000000),
        'role' :  'user'
    }
    
    cookie_string = "email=" + user_object['email'] + "&uid="+str(user_object['uid']) + "&role=" + user_object['role']
    
    return cookie_string
    
def encrypt_profile(encoded):
    key, encrypted = AES_ECB.encrypt(encoded)


def main():
    
    text = input("Enter your E-Mail\n")
    encoded = profile_for(text)
    print(encrypt_profile(encoded))
    
    



if __name__ == "__main__":
    main()