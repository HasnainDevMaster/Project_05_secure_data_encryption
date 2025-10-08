# 🔐 Secure Data Encryption System  

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Framework-Streamlit-FF4B4B?logo=streamlit)
![Encryption](https://img.shields.io/badge/Security-Cryptography-green?logo=databricks)

A **Streamlit-based web application** for securely storing and retrieving sensitive data using **modern encryption** and **hashed authentication** 🔒.  
Designed for users who value **confidentiality**, **data integrity**, and **simplicity** in managing secure information.

---

## 🌐 Live Demo  
🚀 **Access the deployed app here:**  
👉 [Open Secure Data Encryption System](https://hasnaindevmaster-project-05-secure-data-encryption-main-755hbl.streamlit.app/)

---

## ✨ Features & Highlights  

- 👤 **User Registration & Login** — Create accounts and log in with **securely hashed passwords**.  
- 🔒 **Data Encryption** — Encrypt sensitive text using a **user-defined passkey**.  
- 🔓 **Data Retrieval** — Decrypt and view your data safely using the **correct passkey**.  
- 💾 **Persistent Storage** — All encrypted data is stored securely in a local **JSON file**.  
- 🛡 **Security Layers:**  
  - Passwords & passkeys hashed via **PBKDF2-HMAC-SHA256 with salt** 🧂  
  - Data encrypted using **Fernet symmetric encryption** 🔐  
  - **Login attempt limits** + **temporary lockouts** ⏳ to prevent brute-force attacks  

---

## 📁 Project Structure  

```

Project_05_secure_data_encryption/
│
├── main.py              # 🎯 Main Streamlit application
├── requirements.txt     # 📦 Python dependencies
├── secure_data.json     # 🔐 Encrypted user data (auto-generated)
└── .gitattributes       # ⚙️ Git configuration

````

---

## ⚙️ Installation  

1. **Clone this repository**
   ```bash
   git clone https://github.com/HasnainDevMaster/Project_05_secure_data_encryption
   cd Project_05_secure_data_encryption
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage Guide

### 🧾 Register a New User

* Open the app and go to **“Register”** in the sidebar
* Enter a **username** and **password**
* Your credentials are hashed and saved securely

### 🔑 Login

* Head to the **“Login”** page
* Enter your username and password to access the dashboard

### 💬 Store Encrypted Data

* After login, open **“Store Data”**
* Type in your message and a **passkey**
* Click **“Encrypt and Store”** — your entry is saved encrypted 🔐

### 📂 Retrieve Encrypted Data

* Go to **“Retrieve Data”**
* Select an entry and enter the **correct passkey**
* View your decrypted message instantly ✨

---

## 🧠 Security Notes

* ⚠️ **Passwords & passkeys are never stored in plain text**
* 🔑 Each user’s data is encrypted using their **unique passkey**
* ⏳ **3 failed attempts** → temporary **lockout for 60 seconds**
* ❌ Lost passkey? Data **cannot be recovered** (by design)
* 🧩 Uses industry-standard **`cryptography.Fernet`** for robust security

---

## 🧩 Dependencies

📦 Listed in [`requirements.txt`](requirements.txt):

* 🖥️ **Streamlit** → For the interactive web interface
* 🔏 **Cryptography** → For encryption, hashing, and key management

Install all:

```bash
pip install -r requirements.txt
```

---

## 🗂️ File Descriptions

| File               | Description                                                                     |
| ------------------ | ------------------------------------------------------------------------------- |
| `main.py`          | Main application containing encryption logic, authentication, and Streamlit UI. |
| `secure_data.json` | Stores encrypted user data and hashed credentials.                              |
| `requirements.txt` | Python dependencies required for setup.                                         |
| `.gitattributes`   | Git settings and config.                                                        |

---

## 🏆 Summary

This **Secure Data Encryption System** combines **Streamlit’s simplicity** with **powerful cryptography** to create a **secure, interactive data vault** 🔐.
It’s a perfect educational or real-world demonstration of how **authentication**, **encryption**, and **session control** can work seamlessly in Python 🚀.

> 💡 *Ideal for learning, personal data protection, and showcasing secure app design.*

---

**👨‍💻 Developed by [Syed Hasnain Ali Shah](https://github.com/HasnainDevMaster)**
🌟 *Making security simple, strong, and accessible for everyone.*

