#
# Unicode escape format setting dialog for the following plugins:
#   Unicode escape
#   Unicode unescape
#
# Copyright (c) 2020, Nobutaka Mantani
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
import tkinter.ttk

# Print setting to stdout
def print_setting(r, cf, ce):
    escape_format = {"\\uXXXX    (Java, JavaScript)": "\\u",
                     "\\uXXXX and \\UXXXXXXXX    (C, Python)": "\\U",
                     "\\u{XXXX}    (JavaScript ES6+, PHP 7+)": "\\u{",
                     "`u{XXXX}    (PowerShell 6+)": "`u",
                     "%uXXXX    (Legacy JavaScript)": "%u",
                     "U+XXXX    (Unicode code point)": "U+"}
    print("%s\t%s" % (escape_format[cf.get()], ce.get()))
    r.quit()

# Create input dialog
root = tkinter.Tk()
root.title("Unicode escape format setting")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_format = tkinter.Label(root, text="Unicode escape format:")
label_format.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_format = tkinter.ttk.Combobox(root, width=40, state="readonly")
combo_format["values"] = ("\\uXXXX    (Java, JavaScript)",
                          "\\uXXXX and \\UXXXXXXXX    (C, Python)",
                          "\\u{XXXX}    (JavaScript ES6+, PHP 7+)",
                          "`u{XXXX}    (PowerShell 6+)",
                          "%uXXXX    (Legacy JavaScript)",
                          "U+XXXX    (Unicode code point)")
combo_format.current(0)
combo_format.grid(row=0, column=1, padx=5, pady=5, sticky="w")

if len(sys.argv) > 1 and sys.argv[1] == "-e":
    label_encoding = tkinter.Label(root, text="Input encoding:")
elif len(sys.argv) > 1 and sys.argv[1] == "-u":
    label_encoding = tkinter.Label(root, text="Output encoding:")
else:
    label_encoding = tkinter.Label(root, text="Encoding:")

label_encoding.grid(row=1, column=0, padx=5, pady=5, sticky="w")

combo_encoding = tkinter.ttk.Combobox(root, width=10, state="readonly")
combo_encoding["values"] = ("UTF-8", "UTF-16LE", "UTF-16BE")
combo_encoding.current(0)
combo_encoding.grid(row=1, column=1, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text='OK', command=(lambda r=root, cf=combo_format, ce=combo_encoding: print_setting(r, cf, ce)))
button.grid(row=2, column=0, padx=5, pady=5, columnspan=3)

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry('+%d+%d' % ((w/3), (h/2.5)))

root.mainloop()
