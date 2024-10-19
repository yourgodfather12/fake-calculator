import tkinter as tk
from tkinter import filedialog, messagebox, Listbox, Scrollbar
import hashlib
import os
import shutil
import subprocess
from cryptography.fernet import Fernet
import uuid
import base64
import json

# Define the storage directory and metadata file for persistence
STORAGE_DIR = "secure_storage"
METADATA_FILE = os.path.join(STORAGE_DIR, "metadata.json")

# Create the storage folder if it doesn't exist
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)


# Helper function to derive a key from the MAC address
def get_machine_specific_key():
    mac = uuid.getnode()
    return hashlib.sha256(str(mac).encode()).digest()


# Encrypt the password and store it encrypted in the code
def get_encrypted_password():
    key = get_machine_specific_key()
    cipher = Fernet(base64.urlsafe_b64encode(key[:32]))
    encrypted_password = cipher.encrypt(b"12345")  # This is the actual password encrypted
    return encrypted_password


# Decrypt the password at runtime
def decrypt_password():
    key = get_machine_specific_key()
    cipher = Fernet(base64.urlsafe_b64encode(key[:32]))
    return cipher.decrypt(get_encrypted_password()).decode()


# Function to load the file metadata (to persist the stored files)
def load_file_metadata():
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'r') as f:
            return json.load(f)
    else:
        return {}


# Function to save the file metadata
def save_file_metadata(metadata):
    with open(METADATA_FILE, 'w') as f:
        json.dump(metadata, f)


# Variables
expression = ""
file_storage = load_file_metadata()  # Load the metadata of stored files
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# Initialize the main window
root = tk.Tk()
root.title("")  # Set title to blank to make it less suspicious
root.geometry("700x700")
root.configure(bg="#2C3E50")
root.resizable(True, True)

# Add security variables
password_attempts = 0  # Track the number of incorrect attempts
MAX_ATTEMPTS = 3  # Maximum allowed attempts before self-destruct


# Function to evaluate the expression entered
def evaluate_expression():
    global expression, password_attempts

    try:
        # Check if the expression matches the secret password
        entered_password = expression
        decrypted_password = decrypt_password()

        if entered_password == decrypted_password:
            # If the correct password is entered, proceed to the storage locker
            root.after(500, switch_to_storage_locker)  # Smooth transition to the storage locker
        else:
            password_attempts += 1
            if password_attempts >= MAX_ATTEMPTS:
                # If max attempts reached, trigger self-destruct
                self_destruct()
            else:
                entry.delete(0, tk.END)
                entry.insert(tk.END, "Wrong Password!")
        expression = ""
    except Exception as e:
        entry.delete(0, tk.END)
        entry.insert(tk.END, "Error")
        expression = ""


# Function to self-destruct after too many incorrect attempts
def self_destruct():
    # Delete sensitive files and exit
    shutil.rmtree(STORAGE_DIR)
    messagebox.showerror("Security Alert", "Too many incorrect attempts. Self-destructing!")
    root.quit()


# Entry field for the calculator
entry = tk.Entry(root, font=("Arial", 18), justify='right', bg="#1F2E40", fg="white", insertbackground='white')
entry.grid(row=0, column=0, columnspan=4, padx=10, pady=20, sticky="nsew")


# Function to handle button clicks
def on_button_click(char):
    global expression
    expression += str(char)
    entry.delete(0, tk.END)
    entry.insert(tk.END, expression)


# Function to switch the UI to the storage locker
def switch_to_storage_locker(delete_file=None):
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("900x700")  # Expand the window for storage locker
    root.title("Locker")  # Set a neutral title like "Locker"

    # Create a frame to hold the file management section
    main_frame = tk.Frame(root, bg="#2C3E50")
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Title Label
    title = tk.Label(main_frame, text="", font=("Arial", 24), bg="#2C3E50", fg="white")
    title.grid(row=0, column=0, columnspan=3, pady=10)

    # Add category dropdown
    category_label = tk.Label(main_frame, text="Select Category:", font=("Arial", 14), bg="#2C3E50", fg="white")
    category_label.grid(row=1, column=0, sticky="w")

    global category_var
    category_var = tk.StringVar()
    category_var.set("General")

    category_menu = tk.OptionMenu(main_frame, category_var, "General", "Images", "Scripts", "Documents", "Others")
    category_menu.config(font=("Arial", 14), bg="#1F2E40", fg="white", width=12)
    category_menu.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

    # Add file button
    add_file_button = tk.Button(main_frame, text="Add File", font=("Arial", 14), bg="#27AE60", fg="white", command=add_file)
    add_file_button.grid(row=1, column=2, padx=5, pady=5, sticky="ew")

    # Listbox and scrollbar for displaying stored files
    file_frame = tk.Frame(main_frame, bg="#2C3E50")
    file_frame.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=10)

    global file_listbox
    file_listbox = Listbox(file_frame, width=60, height=20, font=("Arial", 12))
    file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Scrollbar
    scrollbar = Scrollbar(file_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    file_listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=file_listbox.yview)

    # Button Frame for actions (Open, Delete)
    button_frame = tk.Frame(main_frame, bg="#2C3E50")
    button_frame.grid(row=3, column=0, columnspan=3, pady=10)

    # Open file button
    open_file_button = tk.Button(button_frame, text="Open Selected File", font=("Arial", 14), bg="#3498DB", fg="white", command=open_file)
    open_file_button.grid(row=0, column=0, padx=5)

    # Delete file button
    delete_file_button = tk.Button(button_frame, text="Delete Selected File", font=("Arial", 14), bg="#E74C3C", fg="white", command=delete_file)
    delete_file_button.grid(row=0, column=1, padx=5)

    # Stretchable layout
    main_frame.grid_rowconfigure(2, weight=1)
    main_frame.grid_columnconfigure(1, weight=1)

    # Display stored files in the listbox
    refresh_file_list()

# Function to add a file to the storage locker
def add_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        category = category_var.get()
        encrypted_file = encrypt_file(file_path)

        # Store the encrypted file in the storage folder
        file_name = os.path.basename(file_path)
        storage_path = os.path.join(STORAGE_DIR, f"{file_name}.enc")
        shutil.copy(encrypted_file, storage_path)

        # Update metadata
        if category not in file_storage:
            file_storage[category] = []
        file_storage[category].append(storage_path)
        save_file_metadata(file_storage)

        refresh_file_list()  # Update the listbox


# Function to refresh the listbox with the current stored files
def refresh_file_list():
    file_listbox.delete(0, tk.END)  # Clear the listbox
    category = category_var.get()
    if category in file_storage:
        for file in file_storage[category]:
            file_listbox.insert(tk.END, os.path.basename(file))  # Insert file names into listbox


# Function to open a selected file from the storage locker
def open_file():
    try:
        selected_file_index = file_listbox.curselection()[0]  # Get the selected file index
        selected_file = file_storage[category_var.get()][selected_file_index]  # Get the file path

        decrypted_file = decrypt_file(selected_file)

        # Open the file using the default application for its file type
        if os.name == "nt":  # For Windows
            os.startfile(decrypted_file)
        elif os.name == "posix":  # For macOS/Linux
            subprocess.Popen(["open", decrypted_file] if "darwin" in os.sys.platform else ["xdg-open", decrypted_file])
    except IndexError:
        messagebox.showwarning("Warning", "No file selected!")


# Function to encrypt a file
def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(file_data)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)

    return encrypted_file_path


# Function to decrypt a file
def decrypt_file(encrypted_file_path):
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    decrypted_file_path = encrypted_file_path.replace(".enc", "")
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    return decrypted_file_path


# Create buttons for the calculator
buttons = [
    ('7', 1, 0), ('8', 1, 1), ('9', 1, 2), ('/', 1, 3),
    ('4', 2, 0), ('5', 2, 1), ('6', 2, 2), ('*', 2, 3),
    ('1', 3, 0), ('2', 3, 1), ('3', 3, 2), ('-', 3, 3),
    ('0', 4, 0), ('.', 4, 1), ('=', 4, 2), ('+', 4, 3)
]

# Function to create buttons and bind events
for (text, row, col) in buttons:
    if text == "=":
        tk.Button(root, text=text, font=("Arial", 16), bg="#34495E", fg="white", command=evaluate_expression).grid(
            row=row, column=col, padx=5, pady=5, sticky="nsew")
    else:
        tk.Button(root, text=text, font=("Arial", 16), bg="#34495E", fg="white",
                  command=lambda char=text: on_button_click(char)).grid(row=row, column=col, padx=5, pady=5,
                                                                        sticky="nsew")

# Add the clear button
clear_button = tk.Button(root, text="C", font=("Arial", 16), bg="#E74C3C", fg="white",
                         command=lambda: entry.delete(0, tk.END))
clear_button.grid(row=4, column=3, padx=5, pady=5, sticky="nsew")

# Start the Tkinter event loop
root.mainloop()
