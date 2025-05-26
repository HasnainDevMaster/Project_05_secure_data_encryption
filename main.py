import streamlit as st
import hashlib
import time
import json
import os
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet

# Secure configuration
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60
DATA_FILE = "secure_data.json"

# Load user data from file
def load_user_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

# Save user data to file
def save_user_data():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.user_data, f)

# Utility Functions
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key[:32])

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    cipher = Fernet(generate_key(passkey))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Session State Initialization
if "user_data" not in st.session_state:
    st.session_state.user_data = load_user_data()
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "decryption_attempts" not in st.session_state:
    st.session_state.decryption_attempts = 0

# UI Header
st.title("🔐 Secure Data Encryption System")

# Logout Button
if st.session_state.authenticated_user:
    with st.sidebar:
        if st.button("🚪 Logout"):
            st.session_state.authenticated_user = None
            st.session_state.failed_attempts = 0
            st.session_state.decryption_attempts = 0
            st.success("✅ Successfully logged out.")

# Navigation
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Pages
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("""
    This app provides secure storage of your sensitive data with encryption.
    - Encrypted persistent data
    - Hashed passwords
    - Limited login and decryption attempts
    """)

elif choice == "Register":
    st.subheader("📝 Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in st.session_state.user_data:
                st.warning("⚠️ Username already exists.")
            else:
                st.session_state.user_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_user_data()
                st.success("✅ Registered successfully.")
        else:
            st.warning("⚠️ Please fill in all fields.")

elif choice == "Login":
    st.subheader("🔑 Login")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Locked out. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in st.session_state.user_data and \
           st.session_state.user_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {remaining}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error(f"🚫 Too many attempts. Locked for {LOCKOUT_DURATION} seconds.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption passkey", type="password")
        if st.button("Encrypt and Store"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                hashed_passkey = hash_password(passkey)
                entry = {
                    "encrypted_text": encrypted,
                    "passkey": hashed_passkey
                }
                st.session_state.user_data[st.session_state.authenticated_user]["data"].append(entry)
                save_user_data()
                st.success("✅ Data encrypted and stored securely.")
            else:
                st.error("❗ All fields are required.")


elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_data = st.session_state.user_data[st.session_state.authenticated_user]["data"]
        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            st.write("🧾 Encrypted Entries:")
            for i, item in enumerate(user_data):
                if isinstance(item, dict) and "encrypted_text" in item:
                    st.code(f"{i+1}: {item['encrypted_text']}", language="text")
                else:
                    st.code(f"{i+1}: [Invalid entry format]", language="text")


            index = st.number_input("Enter entry number to decrypt", min_value=1, max_value=len(user_data), step=1)
            passkey = st.text_input("Decryption passkey", type="password")
            if st.button("Decrypt"):
                selected_entry = user_data[index - 1]
                hashed_input_passkey = hash_password(passkey)

                if hashed_input_passkey == selected_entry["passkey"]:
                    decrypted = decrypt_text(selected_entry["encrypted_text"], passkey)
                    if decrypted:
                        st.success(f"✅ Decrypted Data: {decrypted}")
                        st.session_state.decryption_attempts = 0
                    else:
                        st.error("❌ Failed to decrypt. Data may be corrupted.")
                else:
                    st.session_state.decryption_attempts += 1
                    attempts_left = 3 - st.session_state.decryption_attempts
                    if attempts_left > 0:
                        st.error(f"❌ Invalid passkey. Attempts left: {attempts_left}")
                    else:
                        st.error("❌ Too many failed attempts. Logging out.")
                        st.session_state.authenticated_user = None
                        st.session_state.decryption_attempts = 0
                        st.stop()

