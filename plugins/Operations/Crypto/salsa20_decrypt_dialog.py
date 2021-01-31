#
# Salsa20 decrypt / encrypt - Decrypt / encrypt selected region with Salsa20
#
# Copyright (c) 2019, Nobutaka Mantani
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import binascii
import re
import sys
import time
import tkinter
import tkinter.ttk
import tkinter.messagebox

try:
    import Cryptodome.Cipher.Salsa20
except ImportError:
    exit(-1) # PyCryptodome is not installed

# Print selected items
def decrypt(data, root, ckt, ek, cnt, en):
    key_type = ckt.get()
    key = ek.get()
    nonce_type = cnt.get()
    nonce = en.get()

    if key_type == "Hex":
        if re.match("^([0-9A-Fa-f]{2})+$", key):
            key = binascii.a2b_hex(key)
        else:
            tkinter.messagebox.showerror("Error:", message="Key is not in hex format.")
            return
    else:
        key = key.encode()

    if nonce_type == "Hex":
        if re.match("^([0-9A-Fa-f]{2})+$", nonce):
            nonce = binascii.a2b_hex(nonce)
        else:
            tkinter.messagebox.showerror("Error:", message="Nonce is not in hex format.")
            return
    else:
        nonce = nonce.encode()

    if len(key) != 16 and len(key) != 32:
        tkinter.messagebox.showerror("Error:", message="Key size must be 16 bytes or 32 bytes.")
        return

    len_nonce = len(nonce)
    if len_nonce != 8:
        tkinter.messagebox.showerror("Error:", message="Nonce size must be 8 bytes.")
        return

    try:
        cipher = Cryptodome.Cipher.Salsa20.new(key=key, nonce=nonce)
        d = cipher.decrypt(data)
    except Exception as e:
        tkinter.messagebox.showerror("Error:", message=e)
        root.quit()
        exit(1) # Not decrypted

    sys.stdout.buffer.write(d)
    root.quit()
    exit(0) # Decrypted successfully

# Receive data
data = sys.stdin.buffer.read()

# Create input dialog
root = tkinter.Tk()
root.title("Salsa20 decrypt / encrypt")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_key_type = tkinter.Label(root, text="Key type:")
label_key_type.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_key_type = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_key_type["values"] = ("Text", "Hex")
combo_key_type.current(0)
combo_key_type.grid(row=0, column=1, padx=5, pady=5)

label_key = tkinter.Label(root, text="Key:")
label_key.grid(row=0, column=2, padx=5, pady=5, sticky="w")

entry_key = tkinter.Entry(width=32)
entry_key.grid(row=0, column=3, padx=5, pady=5, sticky="w")

label_nonce_type = tkinter.Label(root, text="Nonce type:")
label_nonce_type.grid(row=1, column=0, padx=5, pady=5, sticky="w")

combo_nonce_type = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_nonce_type["values"] = ("Text", "Hex")
combo_nonce_type.current(0)
combo_nonce_type.grid(row=1, column=1, padx=5, pady=5)

label_nonce = tkinter.Label(root, text="Nonce:")
label_nonce.grid(row=1, column=2, padx=5, pady=5, sticky="w")

entry_nonce = tkinter.Entry(width=32)
entry_nonce.grid(row=1, column=3, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda data=data, root=root, ckt=combo_key_type, ek=entry_key, cnt=combo_nonce_type, en=entry_nonce: decrypt(data, root, ckt, ek, cnt, en)))
button.grid(row=2, column=0, padx=5, pady=5, columnspan=4)

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/3), (h/3)))

root.mainloop()
exit(1) # Not decrypted
