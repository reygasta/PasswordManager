import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import os
import base64
import shutil
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sv_ttk

class DatabaseManager:
    """Handles all interactions with the SQLite database."""
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.setup_database()

    def setup_database(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_name TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                note TEXT,
                last_updated TEXT NOT NULL,
                is_recycled INTEGER NOT NULL DEFAULT 0
            )
        ''')
        self.conn.commit()

    def is_setup_complete(self):
        self.cursor.execute("SELECT 1 FROM meta WHERE key IN ('salt', 'encrypted_pin')")
        return len(self.cursor.fetchall()) == 2

    def save_salt(self, salt):
        self.cursor.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ('salt', salt))
        self.conn.commit()

    def load_salt(self):
        self.cursor.execute("SELECT value FROM meta WHERE key = 'salt'")
        result = self.cursor.fetchone()
        return result[0] if result else None

    def save_pin(self, encrypted_pin):
        self.cursor.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ('encrypted_pin', encrypted_pin.encode()))
        self.conn.commit()

    def load_pin(self):
        self.cursor.execute("SELECT value FROM meta WHERE key = 'encrypted_pin'")
        result = self.cursor.fetchone()
        return result[0].decode() if result else None
    
    def get_account_by_name(self, account_name):
        self.cursor.execute("SELECT * FROM accounts WHERE account_name = ?", (account_name,))
        return self.cursor.fetchone()

    def get_all_accounts(self, recycled=False):
        query = "SELECT account_name, username, encrypted_password, note, last_updated FROM accounts WHERE is_recycled = ? ORDER BY account_name"
        self.cursor.execute(query, (1 if recycled else 0,))
        return self.cursor.fetchall()

    def add_account(self, account_name, username, encrypted_password, note, last_updated):
        try:
            self.cursor.execute(
                "INSERT INTO accounts (account_name, username, encrypted_password, note, last_updated) VALUES (?, ?, ?, ?, ?)",
                (account_name, username, encrypted_password, note, last_updated)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def update_account(self, old_name, new_name, username, encrypted_password, note, last_updated):
        self.cursor.execute(
            "UPDATE accounts SET account_name = ?, username = ?, encrypted_password = ?, note = ?, last_updated = ? WHERE account_name = ?",
            (new_name, username, encrypted_password, note, last_updated, old_name)
        )
        self.conn.commit()
        
    def set_account_recycled_status(self, account_name, is_recycled):
        self.cursor.execute("UPDATE accounts SET is_recycled = ? WHERE account_name = ?", (1 if is_recycled else 0, account_name))
        self.conn.commit()

    def delete_permanently(self, account_name):
        self.cursor.execute("DELETE FROM accounts WHERE account_name = ? AND is_recycled = 1", (account_name,))
        self.conn.commit()

    def re_encrypt_all_data(self, old_fernet, new_fernet):
        all_accounts = self.get_all_accounts(recycled=False) + self.get_all_accounts(recycled=True)
        for name, _, enc_pass, _, _ in all_accounts:
            try:
                decrypted_pass = old_fernet.decrypt(enc_pass.encode()).decode()
                new_encrypted_pass = new_fernet.encrypt(decrypted_pass.encode()).decode()
                self.cursor.execute("UPDATE accounts SET encrypted_password = ? WHERE account_name = ?", (new_encrypted_pass, name))
            except Exception as e:
                print(f"Could not re-encrypt password for {name}: {e}")
        self.conn.commit()
        
    def search_accounts(self, search_term):
        query = "SELECT account_name, username, encrypted_password, note, last_updated FROM accounts WHERE is_recycled = 0 AND account_name LIKE ? ORDER BY account_name"
        self.cursor.execute(query, (f'%{search_term}%',))
        return self.cursor.fetchall()
        
    def close(self):
        self.conn.close()

class PasswordManager:
    """Main application class for the Password Manager."""
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("750x550")
        
        self.vault_dir = "vault"
        self.backups_dir = "backups"
        self.MAX_BACKUPS = 10
        self.setup_directories()
        
        self.db = DatabaseManager(os.path.join(self.vault_dir, "passwords.db"))
        
        self.fernet = None
        self.master_key = None
        self.salt = None
        self.last_activity = datetime.now()
        self.auto_lock_duration = timedelta(hours=1)
        self.show_all_passwords = False
        self.is_dark_theme = False

        self.initialize_security()
        self.setup_theme()
        self.create_login_screen()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_theme(self):
        sv_ttk.set_theme("light")
        try:
            self.is_dark_theme = sv_ttk.get_theme() == "dark"
        except Exception:
            self.is_dark_theme = False
        sv_ttk.set_theme("dark" if self.is_dark_theme else "light")

    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        sv_ttk.set_theme("dark" if self.is_dark_theme else "light")

    def on_closing(self):
        self.db.close()
        self.root.destroy()
        
    def setup_directories(self):
        for dir_path in [self.vault_dir, self.backups_dir]:
            os.makedirs(dir_path, exist_ok=True)

    def initialize_security(self):
        self.salt = self.db.load_salt()
        if not self.salt:
            self.salt = os.urandom(16)
            self.db.save_salt(self.salt)

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        return kdf.derive(password.encode())

    def create_login_screen(self):
        self.clear_screen()
        if not self.db.is_setup_complete():
            self.create_initial_setup()
        else:
            frame = ttk.Frame(self.root, padding=20)
            frame.pack(expand=True)
            ttk.Label(frame, text="Enter Master Password").pack(pady=5)
            self.password_entry = ttk.Entry(frame, show="*")
            self.password_entry.pack(pady=5, padx=20)
            ttk.Label(frame, text="Enter 6-Digit PIN").pack(pady=5)
            self.pin_entry = ttk.Entry(frame, show="*")
            self.pin_entry.pack(pady=5, padx=20)
            ttk.Button(frame, text="Login", command=self.verify_credentials, style="Accent.TButton").pack(pady=10)

    def create_initial_setup(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        ttk.Label(frame, text="Set Master Password").pack(pady=5)
        master_entry = ttk.Entry(frame, show="*")
        master_entry.pack(pady=5, padx=20)
        ttk.Label(frame, text="Set 6-Digit PIN").pack(pady=5)
        pin_entry = ttk.Entry(frame, show="*")
        pin_entry.pack(pady=5, padx=20)
        ttk.Button(frame, text="Submit", command=lambda: self.save_initial_credentials(master_entry.get(), pin_entry.get()), style="Accent.TButton").pack(pady=10)

    def create_main_screen(self):
        self.clear_screen()
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill="both", expand=True)

        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill="x", pady=5)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, pady=5)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", lambda e: self.search_account())

        add_frame = ttk.LabelFrame(main_frame, text="Add New Account", padding=10)
        add_frame.pack(fill="x", pady=10, padx=5)
        ttk.Label(add_frame, text="Account Name").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.account_entry = ttk.Entry(add_frame)
        self.account_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(add_frame, text="Email/Username").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = ttk.Entry(add_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(add_frame, text="Password").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.password_account_entry = ttk.Entry(add_frame, show="*")
        self.password_account_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(add_frame, text="Notes").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.note_entry = ttk.Entry(add_frame)
        self.note_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(add_frame, text="Add Account", command=self.add_account, style="Accent.TButton").grid(row=4, column=1, pady=10, padx=5, sticky="e")
        add_frame.columnconfigure(1, weight=1)

        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill="both", expand=True, pady=5, padx=5)
        columns = ("Account", "Email/Username", "Password", "Notes", "Date")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        for col in columns: self.tree.heading(col, text=col)
        self.tree.column("Password", width=150); self.tree.column("Account", width=150); self.tree.column("Email/Username", width=150)
        self.tree.pack(side=tk.LEFT, fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
        btn_pane_top = ttk.Frame(main_frame)
        btn_pane_top.pack(fill="x", pady=(5,0), padx=5)
        ttk.Button(btn_pane_top, text="✏️ Edit", command=self.edit_account).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_pane_top, text="♻️ Recycle", command=self.move_to_recycle).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_pane_top, text="🗑️ View Recycle Bin", command=self.show_recycle_bin).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_pane_top, text="👁️ Show/Hide Passwords", command=self.toggle_all_passwords).pack(side=tk.LEFT, padx=2)
        
        btn_pane_bottom = ttk.Frame(main_frame)
        btn_pane_bottom.pack(fill="x", pady=(5,5), padx=5)
        ttk.Button(btn_pane_bottom, text="🔑 Change Master Pass", command=self.change_master_password).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_pane_bottom, text="🔢 Change PIN", command=self.change_pin).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_pane_bottom, text="🎨 Toggle Theme", command=self.toggle_theme).pack(side=tk.LEFT, padx=2)

        self.update_table()
        self.check_auto_lock()

    def save_initial_credentials(self, master_password, pin):
        if len(pin) != 6 or not pin.isdigit():
            messagebox.showerror("Error", "PIN must be a 6-digit number!")
            return
        if not master_password:
            messagebox.showerror("Error", "Master Password cannot be empty!")
            return
        self.master_key = self.derive_key(master_password, self.salt)
        self.fernet = Fernet(base64.urlsafe_b64encode(self.master_key))
        encrypted_pin = self.fernet.encrypt(pin.encode()).decode()
        self.db.save_pin(encrypted_pin)
        self.manage_backups()
        self.create_main_screen()

    def verify_credentials(self):
        master_password = self.password_entry.get()
        pin = self.pin_entry.get()
        self.master_key = self.derive_key(master_password, self.salt)
        self.fernet = Fernet(base64.urlsafe_b64encode(self.master_key))
        
        stored_pin_encrypted = self.db.load_pin()
        if not stored_pin_encrypted:
            messagebox.showerror("Error", "Setup is not complete. Please restart.")
            return

        try:
            decrypted_pin = self.fernet.decrypt(stored_pin_encrypted.encode()).decode()
            if decrypted_pin == pin:
                self.last_activity = datetime.now()
                self.create_main_screen()
            else:
                messagebox.showerror("Error", "Incorrect PIN!")
        except Exception:
            messagebox.showerror("Error", "Incorrect Master Password!")

    def add_account(self):
        account = self.account_entry.get()
        username = self.username_entry.get()
        password = self.password_account_entry.get()
        note = self.note_entry.get()
        
        if not (account and username and password):
            messagebox.showwarning("Warning", "Account Name, Username, and Password are required!")
            return
            
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if self.db.add_account(account, username, encrypted_password, note, timestamp):
            self.update_table()
            messagebox.showinfo("Success", "Account saved successfully!")
            for entry in [self.account_entry, self.username_entry, self.password_account_entry, self.note_entry]:
                entry.delete(0, tk.END)
            self.manage_backups()
        else:
            messagebox.showerror("Error", f"Account name '{account}' already exists!")

    def update_table(self, data_source=None):
        self.tree.delete(*self.tree.get_children())
        accounts = data_source if data_source is not None else self.db.get_all_accounts()
        for name, user, enc_pass, note, date in accounts:
            try:
                decrypted_password = self.fernet.decrypt(enc_pass.encode()).decode() if self.show_all_passwords else "●" * 8
            except Exception:
                decrypted_password = "[DECRYPTION FAILED]"
            self.tree.insert("", tk.END, values=(name, user, decrypted_password, note or '', date))

    def search_account(self):
        search_term = self.search_entry.get()
        results = self.db.search_accounts(search_term)
        self.update_table(data_source=results)

    def move_to_recycle(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select an account to recycle!")
            return
            
        account_name = self.tree.item(selected_item)['values'][0]
        if messagebox.askyesno("Confirm", f"Are you sure you want to move '{account_name}' to the Recycle Bin?"):
            self.db.set_account_recycled_status(account_name, is_recycled=True)
            self.update_table()
            messagebox.showinfo("Success", f"Account '{account_name}' has been moved to the Recycle Bin.")
            self.manage_backups()

    def edit_account(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select an account to edit!")
            return
        
        old_name = self.tree.item(selected_item)['values'][0]
        account_data = self.db.get_account_by_name(old_name)
        if not account_data:
            messagebox.showerror("Error", "Could not find the selected account in the database.")
            return
            
        old_user, enc_pass, old_note = account_data[2], account_data[3], account_data[4]

        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit Account")
        
        frame = ttk.Frame(edit_window, padding=10)
        frame.pack(expand=True, fill="both")

        try:
            decrypted_pass = self.fernet.decrypt(enc_pass.encode()).decode()
        except Exception:
            decrypted_pass = "[DECRYPTION FAILED]"
            messagebox.showwarning("Warning", "Could not decrypt password.", parent=edit_window)

        fields = {"Account Name": old_name, "Email/Username": old_user, "Password": decrypted_pass, "Notes": old_note}
        entries = {}
        for i, (text, val) in enumerate(fields.items()):
            ttk.Label(frame, text=text).grid(row=i, column=0, padx=10, pady=5, sticky="w")
            entry = ttk.Entry(frame, width=30)
            entry.grid(row=i, column=1, padx=10, pady=5, sticky="ew")
            entry.insert(0, val or "")
            entries[text] = entry

        def save_changes():
            new_name = entries["Account Name"].get(); new_user = entries["Email/Username"].get(); new_pass = entries["Password"].get(); new_note = entries["Notes"].get()
            if not (new_name and new_user and new_pass):
                messagebox.showerror("Error", "Required fields cannot be empty.", parent=edit_window); return
            new_enc_pass = self.fernet.encrypt(new_pass.encode()).decode()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.db.update_account(old_name, new_name, new_user, new_enc_pass, new_note, timestamp)
            self.search_account()
            self.manage_backups()
            messagebox.showinfo("Success", "Account updated successfully!")
            edit_window.destroy()

        ttk.Button(frame, text="Save", command=save_changes, style="Accent.TButton").grid(row=len(fields), column=1, pady=10, padx=10, sticky="e")
        frame.columnconfigure(1, weight=1)

    def show_recycle_bin(self):
        rb_window = tk.Toplevel(self.root)
        rb_window.title("Recycle Bin")

        frame = ttk.Frame(rb_window, padding=10)
        frame.pack(expand=True, fill="both")
        
        tree = ttk.Treeview(frame, columns=("Account", "Date"), show="headings")
        tree.heading("Account", text="Account Name"); tree.heading("Date", text="Last Updated")
        tree.pack(pady=5, fill="both", expand=True)

        def populate_rb_tree():
            tree.delete(*tree.get_children())
            for name, _, _, _, date in self.db.get_all_accounts(recycled=True):
                tree.insert("", tk.END, values=(name, date))
        populate_rb_tree()

        def restore_account():
            selected = tree.selection()
            if not selected: return
            name = tree.item(selected)['values'][0]
            self.db.set_account_recycled_status(name, is_recycled=False)
            populate_rb_tree()
            self.update_table()
            self.manage_backups()

        def delete_permanently():
            selected = tree.selection()
            if not selected: return
            name = tree.item(selected)['values'][0]
            if messagebox.askyesno("Confirm Deletion", f"PERMANENTLY DELETE '{name}'? This action cannot be undone.", parent=rb_window):
                self.db.delete_permanently(name)
                populate_rb_tree()
                self.manage_backups()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill="x")
        ttk.Button(btn_frame, text="Restore", command=restore_account).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Delete Permanently", command=delete_permanently, style="Accent.TButton").pack(side=tk.RIGHT)

    def toggle_all_passwords(self):
        self.show_all_passwords = not self.show_all_passwords
        self.search_account()

    def manage_backups(self):
        if not os.path.exists(self.db.db_path): return
        
        backup_file_name = f"backup_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.db"
        shutil.copy(self.db.db_path, os.path.join(self.backups_dir, backup_file_name))
        print(f"Backup created: {backup_file_name}")

        try:
            backups = [f for f in os.listdir(self.backups_dir) if f.endswith('.db')]
            if len(backups) > self.MAX_BACKUPS:
                backups.sort(key=lambda f: os.path.getmtime(os.path.join(self.backups_dir, f)))
                num_to_delete = len(backups) - self.MAX_BACKUPS
                for i in range(num_to_delete):
                    file_to_delete = os.path.join(self.backups_dir, backups[i])
                    os.remove(file_to_delete)
                    print(f"Old backup removed: {backups[i]}")
        except Exception as e:
            print(f"Error during backup management: {e}")

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def check_auto_lock(self):
        if datetime.now() - self.last_activity > self.auto_lock_duration:
            self.create_login_screen()
        else:
            self.root.after(60000, self.check_auto_lock)

    def change_master_password(self):
        cp_window = tk.Toplevel(self.root)
        cp_window.title("Change Master Password")
        
        frame = ttk.Frame(cp_window, padding=10)
        frame.pack(expand=True, fill="both")
        
        fields = ["Current Master Password", "Current PIN", "New Master Password", "Confirm New Password"]
        entries = {}
        for text in fields:
            ttk.Label(frame, text=text).pack(pady=(5,0))
            entry = ttk.Entry(frame, show="*", width=40)
            entry.pack(pady=(0,5))
            entries[text] = entry

        def save_new_password():
            current_master = entries["Current Master Password"].get(); current_pin = entries["Current PIN"].get()
            new_master = entries["New Master Password"].get(); confirm_master = entries["Confirm New Password"].get()
            if not all([current_master, current_pin, new_master]):
                messagebox.showerror("Error", "All fields are required.", parent=cp_window); return
            if new_master != confirm_master:
                messagebox.showerror("Error", "New passwords do not match.", parent=cp_window); return
            try:
                temp_key = self.derive_key(current_master, self.salt)
                temp_fernet = Fernet(base64.urlsafe_b64encode(temp_key))
                stored_pin_enc = self.db.load_pin()
                decrypted_pin = temp_fernet.decrypt(stored_pin_enc.encode()).decode()
                if decrypted_pin != current_pin:
                    messagebox.showerror("Error", "Incorrect current password or PIN.", parent=cp_window); return
                
                new_key = self.derive_key(new_master, self.salt)
                new_fernet = Fernet(base64.urlsafe_b64encode(new_key))
                new_pin_enc = new_fernet.encrypt(current_pin.encode()).decode()
                self.db.save_pin(new_pin_enc)
                self.db.re_encrypt_all_data(temp_fernet, new_fernet)
                self.master_key = new_key; self.fernet = new_fernet
                messagebox.showinfo("Success", "Master Password changed successfully!")
                self.manage_backups(); cp_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", "An error occurred. Incorrect current password or PIN.", parent=cp_window); print(e)
        
        ttk.Button(frame, text="Save Changes", command=save_new_password, style="Accent.TButton").pack(pady=10)

    def change_pin(self):
        cpin_window = tk.Toplevel(self.root)
        cpin_window.title("Change PIN")

        frame = ttk.Frame(cpin_window, padding=10)
        frame.pack(expand=True, fill="both")
        
        fields = ["Current PIN", "New 6-Digit PIN", "Confirm New PIN"]
        entries = {}
        for text in fields:
            ttk.Label(frame, text=text).pack(pady=(5,0))
            entry = ttk.Entry(frame, show="*", width=30)
            entry.pack(pady=(0,5))
            entries[text] = entry
        
        def save_new_pin():
            current_pin = entries["Current PIN"].get(); new_pin = entries["New 6-Digit PIN"].get(); confirm_pin = entries["Confirm New PIN"].get()
            if not all([current_pin, new_pin, confirm_pin]):
                messagebox.showerror("Error", "All fields are required.", parent=cpin_window); return
            if new_pin != confirm_pin:
                messagebox.showerror("Error", "New PINs do not match.", parent=cpin_window); return
            if len(new_pin) != 6 or not new_pin.isdigit():
                messagebox.showerror("Error", "New PIN must be a 6-digit number.", parent=cpin_window); return
            try:
                stored_pin_enc = self.db.load_pin()
                decrypted_pin = self.fernet.decrypt(stored_pin_enc.encode()).decode()
                if decrypted_pin != current_pin:
                    messagebox.showerror("Error", "Incorrect current PIN.", parent=cpin_window); return
                
                new_pin_enc = self.fernet.encrypt(new_pin.encode()).decode()
                self.db.save_pin(new_pin_enc)
                messagebox.showinfo("Success", "PIN changed successfully!")
                cpin_window.destroy()
            except Exception:
                 messagebox.showerror("Error", "An error occurred. Failed to change PIN.", parent=cpin_window)

        ttk.Button(frame, text="Save Changes", command=save_new_pin, style="Accent.TButton").pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()