import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import time

# Set page configuration

img_path = "assets/truong.png"
icon_path = "assets/truong.png"

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
    iv = get_random_bytes(16)
    cipher = AES.new(hkey, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), 16))
    return iv + ciphertext

# Define function to decrypt text
def decrypt_text(password, ciphertext, iv):
    hash_obj = SHA256.new(password.encode('utf-8'))
    hkey = hash_obj.digest()
    ciphertext = text_bytes
    cipher = AES.new(hkey, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16).decode('utf-8')
    return plaintext


# Set up sidebar with page title and instructions
st.sidebar.title("AES Encryption/Decryption")
st.sidebar.write("This is a simple tool for encrypting and decrypting text using AES encryption. Enter a password and the text you want to encrypt, then click the 'Encrypt' button. To decrypt, enter the password and upload the encrypted text file.")
st.sidebar.title("Cổng dịch vụ mã hóa, giải mã AES")
st.sidebar.write("Đây là một công cụ đơn giản để mã hóa và giải mã văn bản bằng mã hóa AES. Nhập mật khẩu và văn bản bạn muốn mã hóa, sau đó nhấp vào nút 'Mã hóa'. Để giải mã, hãy nhập mật khẩu và tải lên tệp văn bản được mã hóa.")

# Set up main page layout
header = st.container()
encryption = st.container()
decryption = st.container()

# Set up header section with custom image and title
with header:
    st.image(lock_image, width=100)
    st.title("AES Encryption/Decryption")
    st.subheader("Mode using: CBC")

# Set up encryption section with input fields and button
with encryption:
    st.header("Encryption")
    password = st.text_input("Enter password", type="password", key=1)
    plaintext = st.text_area("Enter text to be encrypted")
    if password and plaintext:
        if st.button("Encrypt"):
            try:
                #start_time = time.perf_counter()
                ciphertext = encrypt_text(password, plaintext)
                
            #     end_time = time.perf_counter()

            # # Calculate the running time in milliseconds
            #     running_time_ms = (end_time - start_time) *1000
            #     print("Decrypt - Running time:", running_time_ms, "milliseconds")
            #     print('....')
                st.success("Text has been encrypted. Click 'Download' to save the encrypted text to a file.")
                
                hex_version = f'- The hex form of encoded text:\n{ciphertext[16:].hex()}'
                iv = f'The iv is:\n{ciphertext[:16]}'
                bform = f'- The bytes form of encoded text:\n{ciphertext[16:]}'
                contents = f'{hex_version}\n\n{iv}\n\n{bform}'
                st.download_button(label="Download", data=contents, file_name="encrypted_text.txt")
            except Exception as e1:
                st.error('There were some errors during the encryption. Please check the information again')
    else:
        st.warning("Please enter a password and text to be encrypted.")

# Set up decryption section with file uploader
with decryption:
    st.header("Decryption")
    password = st.text_input("Enter password", type="password", key ='2')
    file = st.file_uploader("Upload encrypted text file", type = 'txt')
    if file is not None:
        try:
            ####start_time = time.perf_counter()
            # Read lines from file
            lines = file.readlines()
            encrypted_text = lines[1].decode().strip('\n')  #  decode de chuyen chuoi b'' sang string truoc khi .fromhex
            iv = eval(lines[4])
            text_bytes = bytes.fromhex(encrypted_text)
            plaintext = decrypt_text(password, text_bytes, iv)
            ####end_time = time.perf_counter()

            # Calculate the running time in milliseconds
           #### running_time_ms = (end_time - start_time) *1000
            ####print("Decrypt - Running time:", running_time_ms, "milliseconds")
            ####print('....')
            st.success("Text has been decrypted.")
            st.text_area("Decrypted text", value=plaintext)
        except Exception as e:
            st.error('There were some errors during the decryption. Please check the information again')

        