#
# XXTEA decrypt - Decrypt selected region with XXTEA (Corrected Block Tiny Encryption Algorithm)
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
    import Cryptodome.Util.Padding
except ImportError:
    exit(-1) # PyCryptodome is not installed

try:
    import refinery.units.crypto.cipher.xxtea
except ImportError:
    exit(-4) # Binary Refinery is not installed

# Print selected items
def decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs):
    key_size = 16

    mode = cm.get()
    endianness = ce.get()
    key_type = ckt.get()
    key = ek.get()
    iv_type = cit.get()
    iv = ei.get()
    single_block = bsb.get()

    if single_block == True:
        # Treat input data as a single block
        if mode == "CTR":
            tkinter.messagebox.showerror("Error:", message="Treating input data as a single block is not supported with CTR mode.")
            return

        block_size = 1
        if len(data) % 4 == 0:
            block_size_bytes = len(data)
        else:
            block_size_bytes = ((len(data) // 4) + 1) * 4
    else:
        block_size_bytes = int(bs.get())

        # Block size in 32-bit words
        if block_size_bytes % 4 == 0:
            block_size = block_size_bytes // 4
        else:
            tkinter.messagebox.showerror("Error:", message="Block size must be multiple of 4 bytes.")
            return

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

    if mode in ["CFB", "OFB", "CTR"]:
        iv_size = block_size_bytes
    elif mode == "CBC":
        if block_size_bytes % 8 == 0:
            iv_size = block_size_bytes
        else:
            iv_size = ((block_size_bytes // 8) + 1) * 8

    if mode in ["CBC", "CFB", "OFB", "CTR"] and len(iv) != iv_size:
        tkinter.messagebox.showerror("Error:", message="IV size must be %d bytes." % iv_size)
        return

    key_length = len(key)
    if key_length != key_size:
        tkinter.messagebox.showerror("Error:", message="Key size must be %d bytes." % key_size)
        return

    if endianness == "big":
        swap = True
    else:
        swap = False

    try:
        if mode in ["CBC", "CFB", "OFB", "CTR"]:
            cipher = refinery.units.crypto.cipher.xxtea.xxtea(key=key, iv=iv, mode=mode, swap=swap, block_size=block_size)
        elif mode == "ECB":
            cipher = refinery.units.crypto.cipher.xxtea.xxtea(key=key, mode=mode, swap=swap, block_size=block_size)

        d = cipher.process(data=data)
    except Exception as e:
        # Try again with padding="raw"
        try:
            if mode in ["CBC", "CFB", "OFB", "CTR"]:
                cipher = refinery.units.crypto.cipher.xxtea.xxtea(key=key, iv=iv, mode=mode, padding="raw", swap=swap, block_size=block_size)
            elif mode == "ECB":
                cipher = refinery.units.crypto.cipher.xxtea.xxtea(key=key, mode=mode, padding="raw", swap=swap, block_size=block_size)

            d = cipher.process(data=data)
        except Exception as e:
            tkinter.messagebox.showerror("Error:", message=e)
            root.quit()
            exit(1) # Not decrypted

    sys.stdout.buffer.write(d)
    root.quit()
    exit(0) # Decrypted successfully

def combo_mode_selected(root, cm, cit, ei):
    mode = cm.get()
    if mode == "ECB":
        cit.configure(state="disabled")
        ei.configure(state="disabled")
    else:
        cit.configure(state="readonly")
        ei.configure(state="normal")

def block_size_changed(*args, block_size):
    r = block_size.get()
    if not re.match("^([0-9])+$", r):
        block_size.set("8")
    elif int(r) < 8:
        block_size.set("8")

def check_single_block_changed(bool_single_block, spin_block_size):
    if bool_single_block.get() == True:
        spin_block_size.configure(state="disabled")
    else:
        spin_block_size.configure(state="normal")
    return

# Receive data
data = sys.stdin.buffer.read()

# Create input dialog
root = tkinter.Tk()
root.title("XXTEA decrypt")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_mode = tkinter.Label(root, text="Mode:")
label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_mode = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_mode["values"] = ("ECB", "CBC", "CFB", "OFB", "CTR")
combo_mode.current(0)
combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

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

label_endianness = tkinter.Label(root, text="Endianness:")
label_endianness.grid(row=3, column=0, padx=5, pady=5, sticky="w")

combo_endianness = tkinter.ttk.Combobox(root, width=5, state="readonly")
combo_endianness["values"] = ("little", "big")
combo_endianness.current(0)
combo_endianness.grid(row=3, column=1, padx=5, pady=5, sticky="w")

label_single_block = tkinter.Label(root, text="Treat input data as a single block\n(common behaviour of many\nimplementations):", justify="left")
label_single_block.grid(row=4, column=0, padx=5, pady=5, sticky="w", columnspan=3)
bool_single_block = tkinter.BooleanVar()
bool_single_block.set(True)
check_single_block = tkinter.Checkbutton(root, variable=bool_single_block, text="", onvalue=True, offvalue=False, command=lambda: check_single_block_changed(bool_single_block, spin_block_size))
check_single_block.grid(row=4, column=3, padx=5, pady=5, sticky="w")

label_block_size = tkinter.Label(root, text="Block size (bytes):")
label_block_size.grid(row=5, column=0, padx=5, pady=5, sticky="w")

block_size = tkinter.StringVar()
block_size.set("8")
block_size.trace("w", lambda *_, block_size=block_size: block_size_changed(*_, block_size=block_size))
spin_block_size = tkinter.Spinbox(root, textvariable=block_size, width=6, from_=1, to=255)
spin_block_size.grid(row=5, column=1, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs)))
button.grid(row=6, column=0, padx=5, pady=5, columnspan=4)

# Set callback functions
combo_mode.bind('<<ComboboxSelected>>', lambda event, root=root, cm=combo_mode, cit=combo_iv_type, ei=entry_iv: combo_mode_selected(root, cm, cit, ei))
combo_mode.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs))
combo_endianness.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs))
combo_key_type.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs))
entry_key.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs))
combo_iv_type.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs))
entry_iv.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs))
spin_block_size.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs))
button.bind("<Return>", lambda event, data=data, root=root, cm=combo_mode, ce=combo_endianness, ckt=combo_key_type, ek=entry_key, cit=combo_iv_type, ei=entry_iv, bsb=bool_single_block, bs=block_size: decrypt(data, root, cm, ce, ckt, ek, cit, ei, bsb, bs))

# These are disabled in the initial state (ECB mode)
combo_iv_type.configure(state = "disabled")
entry_iv.configure(state = "disabled")

# Disabled in the initial state
spin_block_size.configure(state="disabled")

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
exit(1) # Not decrypted