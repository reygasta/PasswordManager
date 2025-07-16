# Modern Password Manager

A secure, local, and modern password manager built with Python, Tkinter, and SQLite. This application allows you to store and manage your passwords securely on your own computer, with a sleek dark/light mode interface.

![App Screenshot]([https://github.com/user-attachments/assets/518e244d-5c02-42c2-b903-88577908b981](https://private-user-images.githubusercontent.com/122674114/466948091-2e87258a-af9f-4622-aebc-858fc87a792c.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTI2NjMxOTYsIm5iZiI6MTc1MjY2Mjg5NiwicGF0aCI6Ii8xMjI2NzQxMTQvNDY2OTQ4MDkxLTJlODcyNThhLWFmOWYtNDYyMi1hZWJjLTg1OGZjODdhNzkyYy5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwNzE2JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDcxNlQxMDQ4MTZaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0yYjJhZTc5ZDM2ZTQxMjBjYTI5Y2I0MzdiYTRmYTk2YWQ1MDg2Yjk3NDU3NmQwMzAzYzAzMzRhZjk5ZDA4YmY2JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.3PMWfaKUoiVd3bMQl8IxwASAL-ux_mCjnTohhAknJXg))

---

## ✨ Features

* **🔐 Strong Encryption:** Utilizes AES-256 (via Fernet) for data encryption and PBKDF2-HMAC to protect your master password.
* **📂 Centralized Database:** All data is securely stored in a single SQLite database file.
* **🎨 Modern Theming:** Features a beautiful dark/light mode toggle, powered by `sv-ttk`.
* **♻️ Recycle Bin:** "Soft delete" functionality allows you to restore accidentally deleted accounts.
* **🔄 Smart Backups:** An automatic backup system with rotation keeps the last 10 versions of your vault without cluttering your storage.
* **🔍 Quick Search:** Instantly find the account you're looking for.
* **⚙️ Full Credential Management:** Easily change your master password and PIN.
* **🛡️ Offline First:** Operates completely offline. Your data never leaves your computer.

---

## 🛠️ Tech Stack

* **Python 3**
* **Tkinter** (for the GUI)
* **sv-ttk** (for modern themes)
* **SQLite** (for the database)
* **Cryptography** (for encryption)

---

## 🚀 Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/reygasta/PasswordManager.git](https://github.com/reygasta/PasswordManager.git)
    cd PasswordManager
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the application:**
    ```bash
    python main.py
    ```
---

## License

This project is licensed under the MIT License.
