import json
import os
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("500x400")
        self.data = {}
        self.recycled_data = {}  # Store deleted accounts temporarily
        self.fernet = None
        self.show_password = False  # Toggle for password visibility
        self.show_all_passwords = False  # Toggle for showing all passwords
        self.create_login_screen()

    def generate_key(self, master_password):
        # Generate a new encryption key if it doesn't exist
        key_file = 'key.key'
        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
        return master_password.encode()

    def load_key(self):
        # Load the existing encryption key
        with open('key.key', 'rb') as f:
            return f.read()

    def save_data(self):
        # Save encrypted data to files
        if self.data and self.fernet:
            encrypted_data = self.fernet.encrypt(json.dumps(self.data).encode())
            with open('passwords.json', 'wb') as f:
                f.write(encrypted_data)
        if self.recycled_data and self.fernet:
            encrypted_recycled = self.fernet.encrypt(json.dumps(self.recycled_data).encode())
            with open('recycled.json', 'wb') as f:
                f.write(encrypted_recycled)

    def load_data(self):
        # Load and decrypt stored data
        if not os.path.exists('passwords.json'):
            return {}
        with open('passwords.json', 'rb') as f:
            encrypted_data = f.read()
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data).decode()
            return json.loads(decrypted_data)
        except:
            messagebox.showerror("Error", "Incorrect master password or corrupted file!")
            return None

    def load_recycled_data(self):
        # Load and decrypt recycled data
        if not os.path.exists('recycled.json'):
            return {}
        with open('recycled.json', 'rb') as f:
            encrypted_data = f.read()
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data).decode()
            return json.loads(decrypted_data)
        except:
            messagebox.showwarning("Warning", "Recycled bin data corrupted, will be reset.")
            return {}

    def create_login_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Enter Master Password").pack(pady=10)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)
        tk.Button(self.root, text="Login", command=self.verify_password).pack(pady=10)

    def verify_password(self):
        master_password = self.password_entry.get()
        key = self.generate_key(master_password)
        self.fernet = Fernet(key)
        self.data = self.load_data()
        self.recycled_data = self.load_recycled_data()
        if self.data is not None:
            self.create_main_screen()

    def create_main_screen(self):
        self.clear_screen()
        # Add watermark in the top-left corner
        tk.Label(self.root, text="created by reygasta", fg="gray", font=("Arial", 8)).place(x=5, y=5)

        # Form to add a new account
        tk.Label(self.root, text="Account Name").pack()
        self.account_entry = tk.Entry(self.root, width=40)
        self.account_entry.pack(pady=5)
        tk.Label(self.root, text="Email/Username").pack()
        self.username_entry = tk.Entry(self.root, width=40)
        self.username_entry.pack(pady=5)
        tk.Label(self.root, text="Password").pack()
        password_frame = tk.Frame(self.root)
        password_frame.pack(pady=5)
        self.password_account_entry = tk.Entry(password_frame, show="*" if not self.show_password else "", width=35)
        self.password_account_entry.pack(side=tk.LEFT)
        tk.Button(password_frame, text="👁️" if not self.show_password else "👁️‍🗨️", command=self.toggle_password).pack(side=tk.LEFT, padx=5)

        tk.Label(self.root, text="Notes").pack()
        self.note_entry = tk.Entry(self.root, width=40)
        self.note_entry.pack(pady=5)
        tk.Button(self.root, text="Add Account", command=self.add_account).pack(pady=10)

        # Table to display accounts
        self.tree = ttk.Treeview(self.root, columns=("Account", "Email/Username", "Password", "Notes", "Date"), show="headings")
        self.tree.heading("Account", text="Account Name")
        self.tree.heading("Email/Username", text="Email/Username")
        self.tree.heading("Password", text="Password")
        self.tree.heading("Notes", text="Notes")
        self.tree.heading("Date", text="Last Updated")
        self.tree.pack(pady=10, fill="both", expand=True)
        tk.Button(self.root, text="Move to Recycle Bin", command=self.move_to_recycle).pack(pady=5)
        tk.Button(self.root, text="Edit Account", command=self.edit_account).pack(pady=5)
        tk.Button(self.root, text="View Recycle Bin", command=self.show_recycle_bin).pack(pady=5)
        tk.Button(self.root, text="Show All Passwords", command=self.toggle_all_passwords).pack(pady=5)
        self.update_table()

    def toggle_password(self):
        self.show_password = not self.show_password
        current = self.password_account_entry.get()
        self.password_account_entry.delete(0, tk.END)
        self.password_account_entry.config(show="" if self.show_password else "*")
        self.password_account_entry.insert(0, current)

    def toggle_all_passwords(self):
        self.show_all_passwords = not self.show_all_passwords
        self.update_table()

    def move_to_recycle(self):
        selected_item = self.tree.selection()
        if selected_item:
            account = self.tree.item(selected_item)['values'][0]
            if account in self.data:
                self.recycled_data[account] = self.data[account]
                del self.data[account]
                self.save_data()
                self.update_table()
                messagebox.showinfo("Success", f"Account {account} moved to Recycle Bin!")
        else:
            messagebox.showwarning("Warning", "Please select an account to delete!")

    def edit_account(self):
        selected_item = self.tree.selection()
        if selected_item:
            account = self.tree.item(selected_item)['values'][0]
            if account in self.data:
                edit_window = tk.Toplevel(self.root)
                edit_window.title("Edit Account")
                edit_window.geometry("300x200")

                tk.Label(edit_window, text="Account Name").pack(pady=5)
                account_edit = tk.Entry(edit_window, width=30)
                account_edit.insert(0, account)
                account_edit.pack(pady=5)

                tk.Label(edit_window, text="Email/Username").pack(pady=5)
                username_edit = tk.Entry(edit_window, width=30)
                username_edit.insert(0, self.data[account]['username'])
                username_edit.pack(pady=5)

                tk.Label(edit_window, text="Password").pack(pady=5)
                password_frame = tk.Frame(edit_window)
                password_frame.pack(pady=5)
                password_edit = tk.Entry(password_frame, show="*", width=25)
                password_edit.insert(0, self.fernet.decrypt(self.data[account]['password'].encode()).decode())
                password_edit.pack(side=tk.LEFT)
                show_edit = False
                tk.Button(password_frame, text="👁️", command=lambda: self.toggle_edit_password(password_edit, show_edit)).pack(side=tk.LEFT, padx=5)

                tk.Label(edit_window, text="Notes").pack(pady=5)
                note_edit = tk.Entry(edit_window, width=30)
                note_edit.insert(0, self.data[account].get('note', ''))
                note_edit.pack(pady=5)

                def save_edit():
                    new_account = account_edit.get()
                    new_username = username_edit.get()
                    new_password = password_edit.get()
                    new_note = note_edit.get()
                    if new_account and new_username and new_password:
                        if account != new_account and new_account in self.data:
                            messagebox.showerror("Error", "Account name already exists!")
                            return
                        if account in self.data:
                            del self.data[account]
                        self.data[new_account] = {
                            'username': new_username,
                            'password': self.fernet.encrypt(new_password.encode()).decode(),
                            'note': new_note,
                            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        self.save_data()
                        self.update_table()
                        edit_window.destroy()
                        messagebox.showinfo("Success", "Account updated!")
                    else:
                        messagebox.showwarning("Warning", "Please fill all fields!")

                tk.Button(edit_window, text="Save", command=save_edit).pack(pady=10)
        else:
            messagebox.showwarning("Warning", "Please select an account to edit!")

    def toggle_edit_password(self, entry, show_var):
        show_var = not show_var
        current = entry.get()
        entry.delete(0, tk.END)
        entry.config(show="" if show_var else "*")
        entry.insert(0, current)

    def show_recycle_bin(self):
        recycle_window = tk.Toplevel(self.root)
        recycle_window.title("Recycle Bin")
        recycle_window.geometry("400x300")

        tree = ttk.Treeview(recycle_window, columns=("Account", "Email/Username", "Password", "Notes", "Date"), show="headings")
        tree.heading("Account", text="Account Name")
        tree.heading("Email/Username", text="Email/Username")
        tree.heading("Password", text="Password")
        tree.heading("Notes", text="Notes")
        tree.heading("Date", text="Last Updated")
        tree.pack(pady=10, fill="both", expand=True)

        for account, info in self.recycled_data.items():
            decrypted_password = "******"
            tree.insert("", tk.END, values=(account, info['username'], decrypted_password, info.get('note', ''), info.get('last_updated', '')))

        def restore_account():
            selected_item = tree.selection()
            if selected_item:
                account = tree.item(selected_item)['values'][0]
                if account in self.recycled_data:
                    self.data[account] = self.recycled_data[account]
                    del self.recycled_data[account]
                    self.save_data()
                    self.update_table()
                    tree.delete(selected_item)
                    messagebox.showinfo("Success", f"Account {account} restored!")
            else:
                messagebox.showwarning("Warning", "Please select an account to restore!")

        def delete_permanently():
            selected_item = tree.selection()
            if selected_item:
                account = tree.item(selected_item)['values'][0]
                if account in self.recycled_data:
                    del self.recycled_data[account]
                    self.save_data()
                    tree.delete(selected_item)
                    messagebox.showinfo("Success", f"Account {account} permanently deleted!")
            else:
                messagebox.showwarning("Warning", "Please select an account to delete!")

        tk.Button(recycle_window, text="Restore", command=restore_account).pack(pady=5)
        tk.Button(recycle_window, text="Delete Permanently", command=delete_permanently).pack(pady=5)

        # Add "View Password" button for each row in recycle bin
        def toggle_recycle_password(item):
            values = list(tree.item(item, 'values'))
            account = values[0]
            info = self.recycled_data.get(account)
            if info:
                password = self.fernet.decrypt(info['password'].encode()).decode() if values[2] == "******" else "******"
                values[2] = password
                tree.item(item, values=values)

        for item in tree.get_children():
            btn = tk.Button(recycle_window, text="View Password", command=lambda i=item: toggle_recycle_password(i))
            tree.window(item, '#2', window=btn)  # Add button in the second column (Password)

    def clear_screen(self):
        # Clear all widgets from the main window
        for widget in self.root.winfo_children():
            widget.destroy()

    def add_account(self):
        account = self.account_entry.get()
        username = self.username_entry.get()
        password = self.password_account_entry.get()
        note = self.note_entry.get()
        if account and username and password:
            self.data[account] = {
                'username': username,
                'password': self.fernet.encrypt(password.encode()).decode(),
                'note': note,
                'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.save_data()
            self.update_table()
            messagebox.showinfo("Success", "Account saved!")
            # Clear form automatically
            self.account_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_account_entry.delete(0, tk.END)
            self.note_entry.delete(0, tk.END)
            self.show_password = False  # Reset eye button state
            self.password_account_entry.config(show="*")
        else:
            messagebox.showwarning("Warning", "Please fill all fields!")

    def update_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for account, info in self.data.items():
            decrypted_password = self.fernet.decrypt(info['password'].encode()).decode() if self.show_all_passwords else "******"
            self.tree.insert("", tk.END, values=(account, info['username'], decrypted_password, info.get('note', ''), info.get('last_updated', '')))

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()