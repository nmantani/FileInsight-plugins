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

import re
import tkinter
import tkinter.ttk

# Print parameters
def print_param(root, cm, sp, cp, bd):
    mode = cm.get()
    min_len = int(sp.get())
    postprocess = cp.get()
    decode = bd.get()

    print("%s\t%s\t%s\t%s" % (mode, min_len, postprocess, decode))

    root.quit()

def amount_changed(*args):
    if not re.match("^-?([0-9])+$", amount.get()):
        s = re.sub("[^-0-9]", "", amount.get())
        if s == "":
            amount.set("1")
        else:
            amount.set(s)
    elif int(amount.get()) < 1:
        amount.set("1")

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
amount.trace("w", amount_changed)

spin = tkinter.Spinbox(root, textvariable=amount, width=4, from_=1, to=100)
spin.grid(row=1, column=1, padx=5, pady=5, sticky="w")

label_postprocess = tkinter.Label(root, text="Post-process:")
label_postprocess.grid(row=2, column=0, padx=5, pady=5, sticky="w")

combo_postprocess = tkinter.ttk.Combobox(root, width=18, state="readonly")
combo_postprocess["values"] = ("None", "Show offset", "Remove duplicates")
combo_postprocess.current(0)
combo_postprocess.grid(row=2, column=1, padx=5, pady=5, sticky="w")

bool_decode = tkinter.BooleanVar()
bool_decode.set(False)
check_decode = tkinter.Checkbutton(root, variable=bool_decode, text='Decode hex / BASE64 encoded text strings', onvalue=True, offvalue=False)
check_decode.grid(row=3, column=0, padx=5, pady=5, columnspan=2)

button = tkinter.Button(root, text="OK", command=(lambda root=root, cm=combo_mode, sp=spin, cp=combo_postprocess, bd=bool_decode: print_param(root, cm, sp, cp, bd)))
button.grid(row=4, column=0, padx=5, pady=5, columnspan=2)
button.focus() # Focus to this widget

# Set callback functions
for x in (combo_mode, spin, combo_postprocess, check_decode, button):
    x.bind("<Return>", lambda event, root=root, cm=combo_mode, sp=spin, cp=combo_postprocess, bd=bool_decode: print_param(root, cm, sp, cp, bd))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
