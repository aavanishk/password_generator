import random
import string
from tkinter import *
from tkinter import messagebox

# generate a password
def generate_password():
    try:
        length = int(length_entry.get())
        if length < 6:
            messagebox.showerror("Error", "Password length should be at least 6 characters.")
            return
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number.")
        return

    all_characters = string.ascii_letters + string.digits
    if include_special.get():  
        all_characters += string.punctuation

    password = ''.join(random.choice(all_characters) for _ in range(length))
    password_var.set(password)

# copy the generated password to the clipboard
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(password_var.get())
    messagebox.showinfo("Copied", "Password copied to clipboard!")

#  main window
root = Tk()
root.title("Enhanced Password Generator")
root.geometry("450x350")
root.resizable(False, False)
root.configure(background="#1a1a1a")

# Title label
Label(root, text="Password Generator", font=("Helvetica", 18, "bold"), fg="white", bg="#1a1a1a").pack(pady=20)

# input and options
frame = Frame(root, bg="#1a1a1a")
frame.pack(pady=10)

#  password length
Label(frame, text="Password Length:", font=("Helvetica", 12), fg="white", bg="#1a1a1a").grid(row=0, column=0, padx=10, pady=10, sticky=W)
length_entry = Entry(frame, width=5, font=("Helvetica", 12))
length_entry.grid(row=0, column=1, pady=10)

# Checkbox 
include_special = BooleanVar()
include_special_checkbox = Checkbutton(frame, text="Include Special Characters", variable=include_special, font=("Helvetica", 12), fg="white", bg="#1a1a1a", activebackground="#1a1a1a", selectcolor="#333333")
include_special_checkbox.grid(row=1, columnspan=2, pady=10)

# Button to generate password
Button(root, text="Generate Password", command=generate_password, font=("Helvetica", 12), bg="#f04e23", fg="white", width=20).pack(pady=20)

# hold the generated password
password_var = StringVar()

# display the generated password
password_entry = Entry(root, textvariable=password_var, width=30, font=("Helvetica", 14), justify="center", state="readonly")
password_entry.pack(pady=10)

# copy password to clipboard
Button(root, text="Copy to Clipboard", command=copy_to_clipboard, font=("Helvetica", 12), bg="#198754", fg="white", width=20).pack(pady=10)

root.mainloop()
