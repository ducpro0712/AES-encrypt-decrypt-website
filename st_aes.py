import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from PIL import Image

# Set page configuration

img_path = "assets/lock2.png"
icon_path = "assets/lock_icon.png"

st.set_page_config(page_title="AES Encryption/Decryption", page_icon= icon_path, layout="wide", initial_sidebar_state="expanded")
lock_image = Image.open(img_path)

# Set custom color palette
primaryColor="#0b95c5"
backgroundColor="#f9f9f9"
secondaryBackgroundColor="#e6f2f8"
textColor="#252525"

# Define function to encrypt text
def encrypt_text(password, plaintext):
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    message = plaintext
    block_size = 16
    pad = "{"
    padding = lambda s: s + (block_size - len(message) % block_size) * pad
    cipher = AES.new(hkey, AES.MODE_ECB)
    result = cipher.encrypt(padding(message).encode('utf-8'))
    return result

# Define function to decrypt text
def decrypt_text(password, ciphertext):
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    message = ciphertext
    pad = "{"
    decipher = AES.new(hkey, AES.MODE_ECB)
    plaintext = decipher.decrypt(message).decode('utf-8')
    pad_index = plaintext.find(pad)
    result = plaintext[:pad_index]
    return result

# Set up sidebar with page title and instructions
st.sidebar.title("AES Encryption/Decryption")
st.sidebar.write("This is a simple tool for encrypting and decrypting text using AES encryption. Enter a password and the text you want to encrypt, then click the 'Encrypt' button. To decrypt, enter the password and upload the encrypted text file.")

# Set up main page layout
header = st.container()
encryption = st.container()
decryption = st.container()

# Set up header section with custom image and title
with header:
    st.image(lock_image, width=100)
    st.title("AES Encryption/Decryption")
    st.subheader("Mode using: ECB")

# Set up encryption section with input fields and button
with encryption:
    st.header("Encryption")
    password = st.text_input("Enter password", type="password", key=1)
    plaintext = st.text_area("Enter text to be encrypted")
    if st.button("Encrypt"):
        ciphertext = encrypt_text(password, plaintext)
        st.success("Text has been encrypted. Click 'Download' to save the encrypted text to a file.")
        
        hex_version = f'- The hex form of encoded text:\n{ciphertext.hex()}'
        bform = f'- The bytes form of encoded text:\n{ciphertext}'
        pw = f'- Password is:\n{password}'
        contents = f'{hex_version}\n\n{bform}\n\n{pw}'
        st.download_button(label="Download", data=contents, file_name="encrypted_text.txt")


# Set up decryption section with file uploader
with decryption:
    st.header("Decryption")
    password = st.text_input("Enter password", type="password", key ='2')
    file = st.file_uploader("Upload encrypted text file")
    if file is not None:
        try:
            # Read lines from file
            lines = file.readlines()
            encrypted_text = lines[1].decode().strip('\n')
            text_bytes = bytes.fromhex(encrypted_text)
            plaintext = decrypt_text(password, text_bytes)
            st.success("Text has been decrypted.")
            st.text_area("Decrypted text", value=plaintext)
        except UnicodeDecodeError as e1:
            st.error('There was an error because the password or the input has been changed')

        except ValueError as e2:
            st.error('There was an error because the password or the input has been changed')