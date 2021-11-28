#
# Dialog for the following plugins:
# Custom base32 decode
# Custom base32 encode
# Custom base58 decode
# Custom base58 encode
# Custom base62 decode
# Custom base62 encode
# Custom base64 decode
# Custom base64 encode
# Custom base85 decode
# Custom base85 encode
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

import sys
import tkinter

# Print entered table to stdout
def print_table(r, e):
    print(e.get())
    root.quit()

if len(sys.argv) < 3:
    sys.exit(0)
else:
    digits = sys.argv[1]
    action = sys.argv[2]

    if digits == "85":
        table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
    elif digits == "64":
        table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    elif digits == "62":
        table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    elif digits == "58":
        table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    elif digits == "32":
        table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
    elif digits == "16":
        table = "0123456789ABCDEF"
    else:
        sys.exit(1)

# Create input dialog
root = tkinter.Tk()
root.title("Custom base%s %s" % (digits, action))
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label = tkinter.Label(root, text="BASE%s table:" % digits)
label.grid(row=0, column=0, padx=5, pady=5)

entry = tkinter.Entry(root, width=(len(table) + 16))
entry.insert(tkinter.END, table)
entry.grid(row=0, column=1, padx=5, pady=5)
entry.bind("<Return>", lambda event, r=root, e=entry: print_table(r, e)) # Event handler for hitting enter key
entry.focus() # Focus to this widget

button = tkinter.Button(root, text="OK", command=(lambda r=root, e=entry: print_table(r, e)))
button.grid(row=0, column=2, padx=5, pady=5)

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry("+%d+%d" % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
