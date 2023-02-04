import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

col1, col2 = st.columns(2, gap = 'large')

#  ENCODE
with col1:
    
    st.header('Online Encryption')
    st.subheader('AES mode: ECB')
    password =  st.text_input("Enter password", key = 1)
    
    #  bien password thanh 256 bits
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    if password:
        st.write('Password in 256 bits after encoded: ', hkey)
    
    # ham encrypt
    def encrypt(info):
        message = info
        block_size = 16
        pad = "{"
        padding = lambda s: s + (block_size - len(message) % block_size) * pad
        cipher = AES.new(hkey, AES.MODE_ECB)
        result = cipher.encrypt(padding(message).encode('utf-8'))
        return result

    msg = st.text_input('Enter text to be encrypted', key =3)
    
    if st.button("Encrypt"):
        cipher_text = encrypt(msg)
        st.text_area('The bytes form of encoded text', cipher_text)
        
        hex_version = cipher_text.hex()
        st.text_area('The hex form of encoded text', hex_version)
        
        #print(cipher_text)

#  DECODE
with col2:
    
    st.header('Online Decryption')
    st.subheader('AES mode: ECB')
    password =  st.text_input("Enter password", key = 2)
    
    #  bien password thanh 256 bits
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    if password:
        st.write('Password in 256 bits after encoded: ', hkey)
        

    def decrypt(info):
        message = info
       
        pad = "{"
        decipher = AES.new(hkey, AES.MODE_ECB)
        plaintext = decipher.decrypt(message).decode('utf-8')
        pad_index = plaintext.find(pad)
        result = plaintext[:pad_index]
        return result
    
    encoded_text = st.text_input('Enter text in hex format to be decrypted', key = 4)
    text_bytes = bytes.fromhex(encoded_text)
    
    if st.button('Decrypt'):
        pt = decrypt(text_bytes)
        st.text_area('The plain text', pt)

        