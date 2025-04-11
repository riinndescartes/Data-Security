import streamlit as st
import base64
import numpy as np
import hashlib
from PIL import Image
import io
import math

# ====== PLAYFAIR CIPHER FUNCTIONS =======
def generate_playfair_matrix(key):
    key_hash = hashlib.sha256(key.encode()).hexdigest().upper()
    filtered_key = ''.join([c for c in key_hash if c in "ABCDEFGHIKLMNOPQRSTUVWXYZ"])
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    full_key = "".join(dict.fromkeys(filtered_key + alphabet))
    matrix = [list(full_key[i*5:(i+1)*5]) for i in range(5)]
    return matrix

def playfair_value(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return (i, row.index(char))
    return (0, 0)

# ====== MODIFIED RC4 FUNCTIONS =======
def modified_ksa(key):
    key_bytes = [b for b in key]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def modified_prga(S, data_len, playfair_matrix):
    i = 0
    j = 0
    keystream = []
    for _ in range(data_len):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        random_char = chr((K % 26) + 65)
        row, col = playfair_value(playfair_matrix, random_char)
        K = (K + row + col) % 256
        keystream.append(K)
    return keystream

def rc4_playfair_encrypt(data, key):
    playfair_matrix = generate_playfair_matrix(key)
    S = modified_ksa(key.encode())
    keystream = modified_prga(S, len(data), playfair_matrix)
    ciphertext = bytes([d ^ k for d, k in zip(data, keystream)])
    return ciphertext

def rc4_playfair_decrypt(data, key):
    return rc4_playfair_encrypt(data, key)

def bytes_to_image(cipher_bytes, width, height):
    arr = np.frombuffer(cipher_bytes, dtype=np.uint8).reshape((height, width))
    return Image.fromarray(arr)

def image_to_bytes(img):
    return np.array(img).astype(np.uint8).tobytes()

# ===== ENTROPY CALCULATION FUNCTION =====
def calculate_entropy(data):
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / len(data)
            entropy += -p * math.log(p, 2)
    return entropy

# ===== STREAMLIT APP =====
st.title("Modified RC4 + Playfair Cipher")

mode = st.radio("Mode:", ["Encrypt", "Decrypt"])
key = st.text_input("Enter your ASCII key:")
input_type = st.radio("Input Type:", ["Text", "Image (PNG/JPG)", "Other File (Binary)"])

if input_type == "Text":
    plaintext_input = st.text_area("Enter your text:")
elif input_type == "Image (PNG/JPG)":
    uploaded_image = st.file_uploader("Upload an image file:", type=['png', 'jpg', 'jpeg'])
else:
    uploaded_file = st.file_uploader("Upload your file:")

if st.button("Run"):
    if key == "":
        st.error("Please enter a key!")
    else:
        if input_type == "Text":
            data = plaintext_input.encode()
        elif input_type == "Image (PNG/JPG)":
            if uploaded_image is not None:
                image = Image.open(uploaded_image).convert('L')
                data = image.tobytes()
                width, height = image.size
            else:
                st.error("Please upload an image file!")
                st.stop()
        else:
            if uploaded_file is not None:
                data = uploaded_file.read()
            else:
                st.error("Please upload a file!")
                st.stop()

        if mode == "Encrypt":
            result = rc4_playfair_encrypt(data, key)
            st.success("Encryption completed!")

            entropy = calculate_entropy(result)
            st.write(f"Entropi: {entropy:.2f} bit")

            if entropy < 4:
                kategori = "Entropi Bit Rendah (0-4 bit): Keacakan rendah, mudah diprediksi."
            elif 4 <= entropy < 6:
                kategori = "Entropi Bit Sedang (4-6 bit): Keacakan sedang, cukup sulit diprediksi."
            elif 6 <= entropy < 8:
                kategori = "Entropi Bit Tinggi (6-8 bit): Keacakan tinggi, sulit diprediksi."
            else:
                kategori = "Entropi Bit Sangat Tinggi (8+ bit): Keacakan sangat tinggi, hampir tidak mungkin diprediksi."

            st.info(f"Klasifikasi Entropi: {kategori}")

            if input_type == "Text":
                st.text_area("Ciphertext:", value=result.decode(errors='ignore'), height=300)
                b64_result = base64.b64encode(result).decode()
                st.download_button("Download Ciphertext", b64_result, file_name="ciphertext.txt")
            elif input_type == "Image (PNG/JPG)":
                cipher_image = bytes_to_image(result, width, height)
                buf = io.BytesIO()
                cipher_image.save(buf, format="PNG")
                byte_im = buf.getvalue()
                st.download_button("Download Cipher Image", byte_im, file_name="cipher_image.png")
            else:
                st.download_button("Download Cipher File", result, file_name="cipher_output.bin")

        elif mode == "Decrypt":
            result = rc4_playfair_decrypt(data, key)
            st.success("Decryption completed!")

            if input_type == "Text":
                st.text_area("Plaintext:", value=result.decode(errors='ignore'), height=300)
            elif input_type == "Image (PNG/JPG)":
                decrypted_image = bytes_to_image(result, width, height)
                buf = io.BytesIO()
                decrypted_image.save(buf, format="PNG")
                byte_im = buf.getvalue()
                st.download_button("Download Decrypted Image", byte_im, file_name="decrypted_image.png")
            else:
                st.download_button("Download Decrypted File", result, file_name="decrypted_output.bin")
