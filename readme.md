# Secure Data Encryption System

A Streamlit-based web application for securely storing and retrieving sensitive data using encryption and hashed passwords. This project is designed for users who want to keep their confidential information safe with strong cryptography and user authentication.

## Live Demo

Access the deployed app here:  
**[https://hasnaindevmaster-project-05-secure-data-encryption-main-755hbl.streamlit.app/](https://hasnaindevmaster-project-05-secure-data-encryption-main-755hbl.streamlit.app/)**

## Features

- **User Registration & Login:** Register new users and authenticate with hashed passwords.
- **Data Encryption:** Store sensitive data encrypted with a user-provided passkey.
- **Data Retrieval:** Retrieve and decrypt your data using the correct passkey.
- **Persistent Storage:** All user data is stored securely in a JSON file.
- **Security Measures:**
  - Passwords and passkeys are hashed using PBKDF2-HMAC-SHA256 with a salt.
  - Data is encrypted using Fernet symmetric encryption.
  - Limited login and decryption attempts with lockout to prevent brute-force attacks.

## Project Structure

```
.gitattributes
main.py
requirements.txt
secure_data.json
```

- `main.py`: Main Streamlit application.
- `requirements.txt`: Python dependencies.
- `secure_data.json`: Encrypted user data (auto-generated).
- `.gitattributes`: Git configuration.

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/HasnainDevMaster/Project_03_personal_library_manager
   cd Project_05_secure_data_encryption
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

## Usage

1. **Run the application:**
   ```sh
   streamlit run main.py
   ```

2. **Open the app in your browser** (Streamlit will provide a local URL).

3. **Register a new user:**
   - Go to the "Register" page in the sidebar.
   - Enter a username and password.

4. **Login:**
   - Go to the "Login" page.
   - Enter your credentials.

5. **Store Data:**
   - After logging in, go to "Store Data".
   - Enter the data you want to encrypt and a passkey (used for encryption).
   - Click "Encrypt and Store".

6. **Retrieve Data:**
   - Go to "Retrieve Data".
   - Select the entry number and enter the correct passkey to decrypt.

## Security Notes

- **Passwords and passkeys are never stored in plain text.**
- **Each user's data is encrypted with their chosen passkey.**
- **After 3 failed login or decryption attempts, the user is locked out for 60 seconds.**
- **Do not lose your passkey; encrypted data cannot be recovered without it.**

## Dependencies

See [requirements.txt](requirements.txt):

- `streamlit`
- `cryptography`

## File Descriptions

- [`main.py`](main.py): Main application logic, including user authentication, encryption, and UI.
- [`secure_data.json`](secure_data.json): Stores user credentials (hashed) and encrypted data.
- [`requirements.txt`](requirements.txt): Lists required Python packages.
