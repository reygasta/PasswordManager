# Modern Password Manager

A secure, local, and modern password manager built with Python, Tkinter, and SQLite. This application allows you to store and manage your passwords securely on your own computer, with a sleek dark/light mode interface.

![App Screenshot](<img width="1365" height="767" alt="image" src="https://github.com/user-attachments/assets/b2ff50ef-5f7d-401d-8557-c4b8eed07baf" />)


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
