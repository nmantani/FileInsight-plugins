#
# RC6 encrypt - Encrypt selected region with RC6
#
# Copyright (c) 2023, Nobutaka Mantani
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
import tkinter
import tkinter.ttk
import tkinter.messagebox

try:
    import refinery.units.crypto.cipher.rc6
except ImportError:
    exit(-4) # Binary Refinery is not installed

def encrypt(data, root, cm, cks, ckt, ek, cit, ei):
    rc6_key_size = (16, 24, 32)

    mode = cm.get()
    key_size = rc6_key_size[cks.current()]
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

    if len(key) != key_size:
        tkinter.messagebox.showerror("Error:", message="Key size must be %d bytes." % key_size)
        return

    if mode in ["CBC", "CFB", "OFB", "CTR"] and len(iv) != 16: # 128 bits
        tkinter.messagebox.showerror("Error:", message="IV size must be 16 bytes.")
        return

    try:
        if mode in ["CFB", "OFB", "CTR"]:
            cipher = refinery.units.crypto.cipher.rc6.rc6(key=key, iv=iv, mode=mode)
        elif mode == "CBC":
            cipher = refinery.units.crypto.cipher.rc6.rc6(key=key, iv=iv, padding="pkcs7", mode=mode)
        elif mode == "ECB":
            cipher = refinery.units.crypto.cipher.rc6.rc6(key=key, padding="pkcs7", mode=mode)

        c = cipher.reverse(data=data)
    except Exception as e:
        tkinter.messagebox.showerror("Error:", message=e)
        root.quit()
        exit(1) # Not encrypted

    sys.stdout.buffer.write(c)
    root.quit()
    exit(0) # Encrypted successfully

def combo_mode_selected(root, cm, cit, ei):
    mode = cm.get()
    if mode == "ECB":
        cit.configure(state = "disabled")
        ei.configure(state = "disabled")
    else:
        cit.configure(state = "readonly")
        ei.configure(state = "normal")

# Receive data
data = sys.stdin.buffer.read()

# Create input dialog
root = tkinter.Tk()
root.title("RC6 encrypt")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_mode = tkinter.Label(root, text="Mode:")
label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_mode = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_mode["values"] = ("ECB", "CBC", "CFB", "OFB", "CTR")
combo_mode.current(0)
combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

label_key_size = tkinter.Label(root, text="Key size:")
label_key_size.grid(row=0, column=2, padx=5, pady=5, sticky="w")

combo_key_size = tkinter.ttk.Combobox(root, width=20, state="readonly")
combo_key_size["values"] = ("128 bits (16 bytes)", "192 bits (24 bytes)", "256 bits (32 bytes)")
combo_key_size.current(0)
combo_key_size.grid(row=0, column=3, padx=5, pady=5, sticky="w")

label_key_type = tkinter.Label(root, text="Key type:")
label_key_type.grid(row=2, column=0, padx=5, pady=5, sticky="w")

combo_key_type = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_key_type["values"] = ("Text", "Hex")
combo_key_type.current(0)
combo_key_type.grid(row=2, column=1, padx=5, pady=5)

label_key = tkinter.Label(root, text="Key:")
label_key.grid(row=2, column=2, padx=5, pady=5, sticky="w")

entry_key = tkinter.Entry(width=32)
entry_key.grid(row=2, column=3, padx=5, pady=5, sticky="w")
entry_key.focus() # Focus to this widget

label_iv_type = tkinter.Label(root, text="IV type:")
label_iv_type.grid(row=3, column=0, padx=5, pady=5, sticky="w")

combo_iv_type = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_iv_type["values"] = ("Text", "Hex")
combo_iv_type.current(0)
combo_iv_type.grid(row=3, column=1, padx=5, pady=5)

label_iv = tkinter.Label(root, text="IV:")
label_iv.grid(row=3, column=2, padx=5, pady=5, sticky="w")

entry_iv = tkinter.Entry(width=32)
entry_iv.grid(row=3, column=3, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda data=data, root=root, cm=combo_mode, cks=combo_key_size, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, cks, ckt, ek, cit, ei)))
button.grid(row=4, column=0, padx=5, pady=5, columnspan=4)

# Set callback functions
combo_mode.bind('<<ComboboxSelected>>', lambda event, root=root, cm=combo_mode, cit=combo_iv_type, ei=entry_iv: combo_mode_selected(root, cm, cit, ei))
combo_mode.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, cks=combo_key_size, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, cks, ckt, ek, cit, ei))
combo_key_size.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, cks=combo_key_size, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, cks, ckt, ek, cit, ei))
combo_key_type.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, cks=combo_key_size, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, cks, ckt, ek, cit, ei))
entry_key.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, cks=combo_key_size, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, cks, ckt, ek, cit, ei))
combo_iv_type.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, cks=combo_key_size, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, cks, ckt, ek, cit, ei))
entry_iv.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, cks=combo_key_size, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, cks, ckt, ek, cit, ei))
button.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, cks=combo_key_size, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv: encrypt(data, root, cm, cks, ckt, ek, cit, ei))

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
exit(1) # Not encrypted
