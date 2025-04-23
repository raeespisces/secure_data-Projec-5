import streamlit as st
import hashlib
import json
import os
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants
DATA_FILE = "data.json"
KEY_FILE = "secret.key"
LOCKOUT_DURATION = 60  # seconds
MAX_FAILED_ATTEMPTS = 3
backend = default_backend()

# Load or generate a Fernet key
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
cipher = Fernet(key)

# Load data from JSON file
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Track failed attempts and lockout
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# PBKDF2 hashing function
def hash_passkey(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode())).decode()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Save data
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f, indent=4)

# Streamlit UI
st.title("🔒 Multi-User Secure Data System")
menu = ["Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Register":
    st.subheader("👤 Register User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username in stored_data:
            st.error("Username already exists.")
        else:
            salt = os.urandom(16).hex()
            hashed_password = hash_passkey(password, salt)
            stored_data[username] = {"salt": salt, "password": hashed_password, "data": []}
            save_data()
            st.success("User registered successfully!")

elif choice == "Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        st.warning("Account is locked. Try again later.")
    else:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            user = stored_data.get(username)
            if user:
                hashed_input = hash_passkey(password, user['salt'])
                if hashed_input == user['password']:
                    st.session_state.user = username
                    st.session_state.failed_attempts = 0
                    st.success("Login successful!")
                else:
                    st.session_state.failed_attempts += 1
            else:
                st.error("User not found.")

            if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.warning("Too many failed attempts. Account is locked.")

elif choice == "Store Data":
    if "user" not in st.session_state:
        st.warning("Please log in first.")
    else:
        st.subheader("📂 Store Data")
        user_data = st.text_area("Enter Data:")

        if st.button("Encrypt & Save"):
            if user_data:
                encrypted = encrypt_data(user_data)
                stored_data[st.session_state.user]["data"].append(encrypted)
                save_data()
                st.success("Data stored successfully!")
            else:
                st.error("Please enter data.")

elif choice == "Retrieve Data":
    if "user" not in st.session_state:
        st.warning("Please log in first.")
    else:
        st.subheader("🔍 Retrieve Data")
        user_data = stored_data[st.session_state.user]["data"]

        if user_data:
            for i, encrypted in enumerate(user_data):
                st.markdown(f"**Data {i+1}:** {decrypt_data(encrypted)}")
        else:
            st.info("No data found.")
