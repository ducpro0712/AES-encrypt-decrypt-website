import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


st.set_page_config(layout="wide", initial_sidebar_state="expanded")


col1, col2 = st.columns(2, gap = 'large')

#  ENCODE
with col1:
    
    st.header('Online Encryption')
    st.subheader('AES mode: ECB')
    password =  st.text_input(label = "Enter password", key = 1, type = 'password')
    
    #  bien password thanh 256 bits
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    
    # ham encrypt
    def encrypt(info):
        message = info
        block_size = 16
        pad = "{"
        padding = lambda s: s + (block_size - len(message) % block_size) * pad
        cipher = AES.new(hkey, AES.MODE_ECB)
        result = cipher.encrypt(padding(message).encode('utf-8'))
        return result

    msg = st.text_input('Enter text to be encrypted', key =2)
    if st.button("Encrypt"):

        cipher_text = encrypt(msg)
        hex_version = f'- The hex form of encoded text:\n{cipher_text.hex()}'
        bform = f'- The bytes form of encoded text:\n{cipher_text}'
        pw = f'- Password is:\n{password}\n\n- The 256-bits form is:\n{hkey}'

        contents = f'{hex_version}\n\n{bform}\n\n{pw}'
        st.write("Text has been encrypted, click download button to save")
        tai = st.download_button(label = 'Download to file', data= contents, file_name= 'encrypted_text.txt') #mime('application/octet-stream')
        
    
#  DECODE
with col2:
    
    st.header('Online Decryption')
    st.subheader('AES mode: ECB')
    
        
    def decrypt(info,hkey):
        message = info
        pad = "{"
        decipher = AES.new(hkey, AES.MODE_ECB)
        plaintext = decipher.decrypt(message).decode('utf-8')
        pad_index = plaintext.find(pad)
        result = plaintext[:pad_index]
        return result
    
    try:
        password = st.text_input(label = 'Enter password', key = 3, type = 'password')
        hash_obj = SHA256.new(password.encode('utf-8'))
        hkey = hash_obj.digest()
        # Upload file
        file = st.file_uploader("Upload file")
        if file is not None:
        # Read lines from file
            lines = file.readlines()
            #password = lines[7].decode().strip('\n')
            #hash_obj = SHA256.new(password.encode('utf-8'))
           # hkey = hash_obj.digest()
            
            encrypted_text = lines[1].decode().strip('\n')
            text_bytes = bytes.fromhex(encrypted_text)
            pt = decrypt(text_bytes, hkey)
            st.text_area('The plain text', pt)

        

    except UnicodeDecodeError as e1:
        st.error('There was an error because the password or the input has been changed')

    except ValueError as e2:
        st.error('There was an error because the password or the input has been changed')
    
