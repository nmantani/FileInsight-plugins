#
# PPMd decompress - Decompress selected region with PPMd algorithm
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

import io
import re
import sys
import tkinter
import tkinter.ttk

try:
    import ppmd
except ImportError:
    exit(-1) # ppmd-cffi is not installed

def decompress(root, combo_version, spin_order, data):
    version = combo_version.get()
    order = int(spin_order.get())

    io_in = io.BytesIO(data)
    decompressed = b""
    io_out = io.BytesIO(decompressed)
    mem = 32
    restore = 0
    blocksize = 16384

    if version == "8 (version I)":
        decoder = ppmd.Ppmd8Decoder(io_in, order, mem << 20, restore)
    else:
        decoder = ppmd.Ppmd7Decoder(io_in, order, mem << 20)

    try:
        while io_in.tell() < len(data):
            len_remain = len(data) - io_in.tell()

            # XXX: set small blocksize to minimize garbage data at the end of PPMd7 decompressed data
            # because PPMd7 compressed data does not have end mark
            if len_remain < blocksize:
                blocksize = 4

            d = decoder.decode(blocksize)

            if len(d) == 0:
                break
            io_out.write(d)

        decoder.close()
        sys.stdout.buffer.write(io_out.getvalue())
        if version == "7 (version H)":
            print("NOTE: Small amount of data may be appended or truncated at the end of decompressed data", file=sys.stderr)
            print("because size of original data is unknown.", file=sys.stderr)
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

data = sys.stdin.buffer.read()

root = tkinter.Tk()
root.title("PPMd decompress")
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

button = tkinter.Button(root, text="OK", command=(lambda root=root, combo_version=combo_version, spin_order=spin_order, data=data: decompress(root, combo_version, spin_order, data)))
button.grid(row=3, column=0, padx=5, pady=5, columnspan=2)

# Set callback function
combo_version.bind('<<ComboboxSelected>>', (lambda root=root, combo_version=combo_version, order=order: combo_version_changed(root, combo_version, order)))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
