#
# Strings - Extract text strings from selected region (the whole file if not selected)
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

import sys
import time
import tkinter
import tkinter.ttk

# Print parameters
def print_param(root, cm, sp, cp, bd):
    mode = cm.get()
    min_len = int(sp.get())
    postprocess = cp.get()
    decode_hex = bd.get()

    print("%s\t%s\t%s\t%s" % (mode, min_len, postprocess, decode_hex))

    root.quit()

# Create input dialog
root = tkinter.Tk()
root.title("Strings")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_mode = tkinter.Label(root, text="Mode:")
label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_mode = tkinter.ttk.Combobox(root, width=18, state="readonly")
combo_mode["values"] = ("ASCII + UTF-16", "ASCII", "UTF-16")
combo_mode.current(0)
combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

label_length = tkinter.Label(root, text='Minimum length:')
label_length.grid(row=1, column=0, padx=5, pady=5)
amount = tkinter.StringVar()
amount.set("4")
spin = tkinter.Spinbox(root, textvariable=amount, state="readonly", width=4, from_=1, to=100)
spin.grid(row=1, column=1, padx=5, pady=5, sticky="w")

label_postprocess = tkinter.Label(root, text="Post-process:")
label_postprocess.grid(row=2, column=0, padx=5, pady=5, sticky="w")

combo_postprocess = tkinter.ttk.Combobox(root, width=18, state="readonly")
combo_postprocess["values"] = ("None", "Show offset", "Remove duplicates")
combo_postprocess.current(0)
combo_postprocess.grid(row=2, column=1, padx=5, pady=5, sticky="w")

bool_decode_hex = tkinter.BooleanVar()
bool_decode_hex.set(False)
check_decode_hex = tkinter.Checkbutton(root, variable=bool_decode_hex, text='Decode hex-encoded text strings', onvalue=True, offvalue=False)
check_decode_hex.grid(row=3, column=0, padx=5, pady=5, columnspan=2)

button = tkinter.Button(root, text="OK", command=(lambda root=root, cm=combo_mode, sp=spin, cp=combo_postprocess, bd=bool_decode_hex: print_param(root, cm, sp, cp, bd)))
button.grid(row=4, column=0, padx=5, pady=5, columnspan=2)

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/2.5), (h/2.5)))

root.mainloop()
