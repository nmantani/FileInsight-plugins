#
# Triple DES decrypt - Decrypt selected region with Triple DES
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
import Tkinter
import ttk
import tkMessageBox

try:
    import Cryptodome.Cipher.DES3
    import Cryptodome.Util.Padding
except ImportError:
    exit(-1) # PyCryptodome is not installed

# Print selected items
def decrypt(data, root, cm, ckt, ek, cit, ei):
    des_mode = {"ECB":Cryptodome.Cipher.DES3.MODE_ECB,
                "CBC":Cryptodome.Cipher.DES3.MODE_CBC,
                "CFB":Cryptodome.Cipher.DES3.MODE_CFB,
                "OFB":Cryptodome.Cipher.DES3.MODE_OFB}

    mode = cm.get()
    key_type = ckt.get()
    key = ek.get()
    iv_type = cit.get()
    iv = ei.get()

    if key_type == "Hex":
        if re.match("^([0-9A-Fa-f]{2})+$", key):
            key = binascii.a2b_hex(key)
        else:
            tkMessageBox.showerror("Error:", message="Key is not in hex format.")
            return

    if mode in ["CBC", "CFB", "OFB"] and iv_type == "Hex":
        if re.match("^([0-9A-Fa-f]{2})+$", iv):
            iv = binascii.a2b_hex(iv)
        else:
            tkMessageBox.showerror("Error:", message="IV is not in hex format.")
            return

    if mode in ["CBC", "CFB", "OFB"] and len(iv) != 8:
        tkMessageBox.showerror("Error:", message="IV size must be 8 bytes.")
        return

    key_length = len(key)
    if key_length != 24:
        tkMessageBox.showerror("Error:", message="Key size must be 24 bytes.")
        return

    try:
        if mode == "CFB":
            cipher = Cryptodome.Cipher.DES3.new(key, des_mode[mode], iv, segment_size=Cryptodome.Cipher.DES3.block_size * 8)
        elif mode in ["CBC", "OFB"]:
            cipher = Cryptodome.Cipher.DES3.new(key, des_mode[mode], iv)
        else:
            cipher = Cryptodome.Cipher.DES3.new(key, des_mode[mode])

        d = cipher.decrypt(data)

        if mode in ["ECB", "CBC"]:
            d = Cryptodome.Util.Padding.unpad(d, Cryptodome.Cipher.DES3.block_size)
    except Exception as e:
        tkMessageBox.showerror("Error:", message=e)
        root.quit()
        exit(1) # Not decrypted

    sys.stdout.write(binascii.b2a_hex(d))
    root.quit()
    exit(0) # Decrypted successfully

def combo_mode_selected(root, cm, cit, ei):
    mode = cm.get()
    if mode == "ECB":
        cit.configure(state = "disabled")
        ei.configure(state = "disabled")
    else:
        cit.configure(state = "normal")
        ei.configure(state = "normal")

# Receive data
data = binascii.a2b_hex(sys.stdin.read())

# Create input dialog
root = Tkinter.Tk()
root.title("Triple DES Decrypt")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_mode = Tkinter.Label(root, text="Mode:")
label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_mode = ttk.Combobox(root, width=5, state="readonly")
combo_mode["values"] = ("ECB", "CBC", "CFB", "OFB")
combo_mode.current(0)
combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

label_key_type = Tkinter.Label(root, text="Key type:")
label_key_type.grid(row=1, column=0, padx=5, pady=5, sticky="w")

combo_key_type = ttk.Combobox(root, width=5, state="readonly")
combo_key_type["values"] = ("Text", "Hex")
combo_key_type.current(0)
combo_key_type.grid(row=1, column=1, padx=5, pady=5)

label_key = Tkinter.Label(root, text="Key:")
label_key.grid(row=1, column=2, padx=5, pady=5, sticky="w")

entry_key = Tkinter.Entry(width=32)
entry_key.grid(row=1, column=3, padx=5, pady=5, sticky="w")

label_iv_type = Tkinter.Label(root, text="IV type:")
label_iv_type.grid(row=2, column=0, padx=5, pady=5, sticky="w")

combo_iv_type = ttk.Combobox(root, width=5, state="readonly")
combo_iv_type["values"] = ("Text", "Hex")
combo_iv_type.current(0)
combo_iv_type.grid(row=2, column=1, padx=5, pady=5)

label_iv = Tkinter.Label(root, text="IV:")
label_iv.grid(row=2, column=2, padx=5, pady=5, sticky="w")

entry_iv = Tkinter.Entry(width=32)
entry_iv.grid(row=2, column=3, padx=5, pady=5, sticky="w")

button = Tkinter.Button(root, text="OK", command=(lambda data=data, root=root, cm=combo_mode, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: decrypt(data, root, cm, ckt, ek, cit, ei)))
button.grid(row=3, column=0, padx=5, pady=5, columnspan=4)

# Set callback function
combo_mode.bind('<<ComboboxSelected>>', (lambda root=root, cm=combo_mode, cit=combo_iv_type, ei=entry_iv: combo_mode_selected(root, cm, cit, ei)))
# These are disabled in the initial state (ECB mode)
combo_iv_type.configure(state = "disabled")
entry_iv.configure(state = "disabled")

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/3), (h/3)))

root.mainloop()
exit(1) # Not decrypted
