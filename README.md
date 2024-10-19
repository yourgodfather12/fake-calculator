# Hidden Secure Storage Locker in Calculator

This is a simple **calculator** app with a hidden **secure storage locker** feature. It lets you store and encrypt files, hidden behind a regular calculator interface.

## Features

- **Basic Calculator**: Functions as a normal calculator.
- **Hidden Locker**: Enter a password to access the storage locker where you can:
  - Add, open, and delete encrypted files.
  - Organize files by category.
- **Self-Destruct**: After 3 incorrect password attempts, all files are deleted.
- **File Encryption**: Files are securely encrypted using **Fernet**.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/fake-calculator.git
   cd fake-calculator
Install dependencies:
bash
Copy code
pip install cryptography
Run the app:
bash
Copy code
python calculator_locker.py
Usage
Use the calculator normally.
Enter the secret password and press = to access the storage locker.
In the locker, you can add, open, or delete encrypted files.
Customization
Change the password in get_encrypted_password() and decrypt_password() functions.
Modify file categories in the category_menu.
License
This project is licensed under the MIT License.
