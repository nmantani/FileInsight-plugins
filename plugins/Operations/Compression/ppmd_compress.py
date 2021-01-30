#
# PPMd compress - Compress selected region with PPMd algorithm
#
# Copyright (c) 2021, Nobutaka Mantani
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
import io
import re
import sys
import tkinter
import tkinter.ttk
import tkinter.messagebox

try:
    import ppmd
except ImportError:
    exit(-1) # ppmd-cffi is not installed

def compress(root, combo_version, spin_order, data):
    version = combo_version.get()
    order = int(spin_order.get())

    compressed = b""
    io_out = io.BytesIO(compressed)
    mem = 32
    restore = 0

    if version == "8 (version I)":
        encoder = ppmd.Ppmd8Encoder(io_out, order, mem << 20, restore)
    else:
        encoder = ppmd.Ppmd7Encoder(io_out, order, mem << 20)

    try:
        encoder.encode(data)
        encoder.flush()
        encoder.close()
        sys.stdout.write(str(binascii.b2a_hex(io_out.getvalue()).decode()))
    except Exception as e:
        print(e, file=sys.stderr)
        exit(1)

    root.quit()

def combo_version_changed(root, combo_version, order):
    # Set order value to default that is used by 7-Zip
    if combo_version.get() == "8 (version I)":
        order.set("8")
    else: # 7 (version H)
        order.set("6")

def order_changed(*args):
    if not re.match("^-?([0-9])+$", order.get()):
        order.set("6")
    elif int(order.get()) < 2:
        order.set("2")
    elif int(order.get()) > 64:
        order.set("64")

data = binascii.a2b_hex(sys.stdin.read())

root = tkinter.Tk()
root.title("PPMd compress")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_version = tkinter.Label(root, text="PPMd version:")
label_version.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_version = tkinter.ttk.Combobox(root, width=12, state="readonly")
combo_version["values"] = ("7 (version H)", "8 (version I)")
combo_version.current(0)
combo_version.grid(row=0, column=1, padx=5, pady=5, sticky="w")

label_order = tkinter.Label(root, text="Model order (2-64):")
label_order.grid(row=1, column=0, padx=5, pady=5, sticky="w")
order = tkinter.StringVar()
order.set("6")
order.trace("w", order_changed)
spin_order = tkinter.Spinbox(root, textvariable=order, width=4, from_=2, to=64)
spin_order.grid(row=1, column=1, padx=5, pady=5, sticky="w")

label_description = tkinter.Label(root, text="7-Zip uses the following values by default:\nFor .7z files: PPMd version -> 7, Model order -> 6\nFor .zip files: PPMd version -> 8, Model order -> 8", justify="left")
label_description.grid(row=2, column=0, padx=5, pady=0, columnspan=2, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda root=root, combo_version=combo_version, spin_order=spin_order, data=data: compress(root, combo_version, spin_order, data)))
button.grid(row=3, column=0, padx=5, pady=5, columnspan=2)

# Set callback function
combo_version.bind('<<ComboboxSelected>>', (lambda root=root, combo_version=combo_version, order=order: combo_version_changed(root, combo_version, order)))

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/2.5), (h/2.5)))

root.mainloop()
