#
# AES encrypt - Encrypt selected region with AES
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
    import Cryptodome.Cipher.AES
    import Cryptodome.Util.Padding
except ImportError:
    exit(-1) # PyCryptodome is not installed

# Print selected items
def encrypt(data, root, cm, ckl, ckt, ek, cit, ei):
    aes_mode = {"ECB":Cryptodome.Cipher.AES.MODE_ECB,
                "CBC":Cryptodome.Cipher.AES.MODE_CBC,
                "CFB":Cryptodome.Cipher.AES.MODE_CFB,
                "OFB":Cryptodome.Cipher.AES.MODE_OFB,
                "CTR":Cryptodome.Cipher.AES.MODE_CTR}
    aes_key_length = (16, 24 ,32)

    mode = cm.get()
    key_length = aes_key_length[ckl.current()]
    key_type = ckt.get()
    key = ek.get()
    iv_type = cit.get()
    iv = ei.get()

    if key_type == "Hex":
        if re.match("^([0-9A-Fa-f]{2})+$", key):
            key = binascii.a2b_hex(key)
        else:
            tkinter.messagebox.showerror("Error:", message="Key is not in hex format.")
            return
    else:
        key = key.encode()

    if mode in ["CBC", "CFB", "OFB", "CTR"] and iv_type == "Hex":
        if re.match("^([0-9A-Fa-f]{2})+$", iv):
            iv = binascii.a2b_hex(iv)
        else:
            tkinter.messagebox.showerror("Error:", message="IV is not in hex format.")
            return
    else:
        iv = iv.encode()

    if mode in ["CBC", "CFB", "OFB", "CTR"] and len(iv) != Cryptodome.Cipher.AES.block_size:
        tkinter.messagebox.showerror("Error:", message="IV size must be %d bytes." % Cryptodome.Cipher.AES.block_size)
        return

    if len(key) != key_length:
        tkinter.messagebox.showerror("Error:", message="Key size must be %d bytes." % key_length)
        return

    try:
        if mode == "CFB":
            cipher = Cryptodome.Cipher.AES.new(key, aes_mode[mode], iv, segment_size=Cryptodome.Cipher.AES.block_size * 8)
        elif mode in ["CBC", "OFB"]:
            cipher = Cryptodome.Cipher.AES.new(key, aes_mode[mode], iv)
        elif mode == "CTR": # The first half of IV is used as nonce and the second half is used as initial_value (compatible with CyberChef).
            cipher = Cryptodome.Cipher.AES.new(key, aes_mode[mode], nonce=iv[0:8], initial_value=iv[8:16])
        else:
            cipher = Cryptodome.Cipher.AES.new(key, aes_mode[mode])

        if mode in ["ECB", "CBC"]:
            data = Cryptodome.Util.Padding.pad(data, Cryptodome.Cipher.AES.block_size)

        d = cipher.encrypt(data)
    except Exception as e:
        tkinter.messagebox.showerror("Error:", message=e)
        root.quit()
        exit(1) # Not decrypted

    sys.stdout.buffer.write(d)
    root.quit()
    exit(0) # Decrypted successfully

def combo_mode_selected(root, cm, cit, ei, lc):
    mode = cm.get()
    if mode == "ECB":
        cit.configure(state = "disabled")
        ei.configure(state = "disabled")
    else:
        cit.configure(state = "readonly")
        ei.configure(state = "normal")

    if mode == "CTR":
        lc.grid()
    else:
        lc.grid_remove()

# Receive data
data = sys.stdin.buffer.read()

# Create input dialog
root = tkinter.Tk()
root.title("AES Encrypt")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_mode = tkinter.Label(root, text="Mode:")
label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_mode = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_mode["values"] = ("ECB", "CBC", "CFB", "OFB", "CTR")
combo_mode.current(0)
combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

label_key_length = tkinter.Label(root, text="Key length:")
label_key_length.grid(row=0, column=2, padx=5, pady=5, sticky="w")

combo_key_length = tkinter.ttk.Combobox(root, width=20, state="readonly")
combo_key_length["values"] = ("128 bits (16 bytes)", "192 bits (24 bytes)", "256 bits (32 bytes)")
combo_key_length.current(0)
combo_key_length.grid(row=0, column=3, padx=5, pady=5, sticky="w")

label_key_type = tkinter.Label(root, text="Key type:")
label_key_type.grid(row=1, column=0, padx=5, pady=5, sticky="w")

combo_key_type = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_key_type["values"] = ("Text", "Hex")
combo_key_type.current(0)
combo_key_type.grid(row=1, column=1, padx=5, pady=5)

label_key = tkinter.Label(root, text="Key:")
label_key.grid(row=1, column=2, padx=5, pady=5, sticky="w")

entry_key = tkinter.Entry(width=32)
entry_key.grid(row=1, column=3, padx=5, pady=5, sticky="w")

label_iv_type = tkinter.Label(root, text="IV type:")
label_iv_type.grid(row=2, column=0, padx=5, pady=5, sticky="w")

combo_iv_type = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_iv_type["values"] = ("Text", "Hex")
combo_iv_type.current(0)
combo_iv_type.grid(row=2, column=1, padx=5, pady=5)

label_iv = tkinter.Label(root, text="IV:")
label_iv.grid(row=2, column=2, padx=5, pady=5, sticky="w")

entry_iv = tkinter.Entry(width=32)
entry_iv.grid(row=2, column=3, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda data=data, root=root, cm=combo_mode, ckl=combo_key_length, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, ckl, ckt, ek, cit, ei)))
button.grid(row=3, column=0, padx=5, pady=5, columnspan=4)

label_ctr = tkinter.Label(root, text="Note:\nThe first half of IV is used as the nonce and the second half is used as\nthe initial value of the counter (compatible with CyberChef).", justify="left")
label_ctr.grid(row=4, column=0, padx=5, pady=5, columnspan=4, sticky="w")
label_ctr.grid_remove()

# Set callback function
combo_mode.bind('<<ComboboxSelected>>', (lambda root=root, cm=combo_mode, cit=combo_iv_type, ei=entry_iv, lc=label_ctr: combo_mode_selected(root, cm, cit, ei, lc)))
# These are disabled in the initial state (ECB mode)
combo_iv_type.configure(state = "disabled")
entry_iv.configure(state = "disabled")

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
exit(1) # Not decrypted
