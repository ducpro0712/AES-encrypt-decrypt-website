import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import binascii
#st.set_page_config(layout="wide", initial_sidebar_state="expanded")
mode_choosing = st.selectbox(label = 'Choose AES mode', options= ('ECB', 'GCM'))

if mode_choosing == 'ECB':
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

        msg = st.text_input('Enter text to be encrypted', key =3)
        if st.button("Encrypt"):

            cipher_text = encrypt(msg)
            hex_version = f'- The hex form of encoded text:\n{cipher_text.hex()}'
            bform = f'- The bytes form of encoded text:\n{cipher_text}'
            pw = f'- Password is:\n{password}\n\n- The 256-bits form is:\n{hkey}'

            contents = f'{hex_version}\n\n{bform}\n\n{pw}'
            st.write("Text has been encrypted, click download button to save")
            tai = st.download_button(label = 'Download to file', data= contents, file_name= 'encrypted_text.txt')
            
        
    #  DECODE
    with col2:
        
        st.header('Online Decryption')
        st.subheader('AES mode: ECB')
        choice = st.selectbox(label = 'Choose mode to decrypt', options= ('Decrypt file', 'Directly tackling'))
            
        def decrypt(info):
            message = info
            pad = "{"
            decipher = AES.new(hkey, AES.MODE_ECB)
            plaintext = decipher.decrypt(message).decode('utf-8')
            pad_index = plaintext.find(pad)
            result = plaintext[:pad_index]
            return result
        
        try:
            if choice == 'Decrypt file':
                # Upload file
                file = st.file_uploader("Upload file")
                if file is not None:
                # Read lines from file
                    lines = file.readlines()
                    
                    password = lines[7].decode().strip('\n')
                    hash_obj = SHA256.new(password.encode('utf-8'))
                    hkey = hash_obj.digest()
                    
                    encrypted_text = lines[1].decode().strip('\n')
                    text_bytes = bytes.fromhex(encrypted_text)
                    pt = decrypt(text_bytes)
                    st.text_area('The plain text', pt)

            else:
                password =  st.text_input("Enter password", key = 2, type = 'password')
                hash_obj = SHA256.new(password.encode('utf-8'))
                hkey = hash_obj.digest()
                encoded_text = st.text_input('Enter text in hex format to be decrypted', key = 4)
                text_bytes = bytes.fromhex(encoded_text)
                pt = decrypt(text_bytes)
                st.text_area('The plain text', pt)

        except UnicodeDecodeError as e1:
            st.error('There was an error because the password or the input has been changed')

        except ValueError as e2:
            st.error('There was an error because the password or the input has been changed')
    
else:
    st.title("AES Encryption and Decryption")
    st.header("Using Mode: GCM")

    #  create 256bits password 
    password =  st.text_input("Enter password", key = 1, type= 'password')
    hash_o = SHA256.new(password.encode('utf-8'))
    key = hash_o.digest()


    # encrypt function
    def encrypt(plaintext,key, mode):
        encobj = AES.new(key, AES.MODE_GCM)
        ciphertext,authTag = encobj.encrypt_and_digest(plaintext)
        return (ciphertext, authTag, encobj.nonce)

    #  decrypt function
    def decrypt(ciphertext,key, mode):
        (ciphertext,  authTag, nonce) = ciphertext
        encobj = AES.new(key,  mode, nonce)
        return (encobj.decrypt_and_verify(ciphertext, authTag))

    #  input
    text = st.text_area('Enter something...')

    #  start encrypt
    ciphertext = encrypt(text.encode(), key, AES.MODE_GCM)
    #st.write("Cipher Text: ", binascii.hexlify(ciphertext[0]))
    #st.write("Cipher Text in hex: ", ciphertext[0].hex())
    #st.write("Auth Msg: ", binascii.hexlify(ciphertext[1]))
    #st.write("Nonce: ", binascii.hexlify(ciphertext[2]))

    hex_form = f"Cipher Text in hex:\n{ciphertext[0].hex()}"
    auth_msg = f'Auth msg:\n{binascii.hexlify(ciphertext[1])}'
    non = f'Nonce:\n{binascii.hexlify(ciphertext[2])}'
    contents = f'{hex_form}\n\n{auth_msg}\n\n{non}'

    if st.download_button(label = 'Download to claim data', data = contents, file_name= 'data.txt'):
        st.write('click decrypt button to check the decryption')
    click = st.button("Decrypt")
    if click:

        decrypted = decrypt(ciphertext, key, AES.MODE_GCM)
        st.text_area("Decrypted after encrypted: ", decrypted.decode())
