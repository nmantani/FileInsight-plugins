#
# Delimiter setting dialog for the following plugins:
#   Binary data to decimal text
#   Decimal text to binary data
#   Binary data to octal text
#   Octal text to binary data
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
import tkinter
import tkinter.ttk

# Print delimiter setting to stdout
def print_setting(r, cd, ce, s):
    print("%s\t%s\t%s" % (cd.get(), ce.get(), s.get()))
    root.quit()

def single_int_checked(r, le1, le2, ce):
    if single_int.get():
        le1.grid()
        le2.grid()
        ce.grid()
    else:
        le1.grid_remove()
        le2.grid_remove()
        ce.grid_remove()

single_int_checkbox = False
endianness_menu = False

if len(sys.argv) == 2 and sys.argv[1] == "-e":
    endianness_menu = True
elif len(sys.argv) == 2 and sys.argv[1] == "-s":
    single_int_checkbox = True
else:
    endianness_menu = False

# Create input dialog
root = tkinter.Tk()
root.title("Delimiter setting")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))
label_delimiter = tkinter.Label(root, text="Delimiter:")
label_delimiter.grid(row=0, column=0, padx=5, pady=5, sticky="w")
combo_delimiter = tkinter.ttk.Combobox(root, width=10, state="readonly")
combo_delimiter["values"] = ("Space", "Comma", "Semi-colon", "Colon", "Tab", "LF", "CRLF")
combo_delimiter.current(0)
combo_delimiter.grid(row=0, column=1, padx=5, pady=5, sticky="w")

label_endianness1 = tkinter.Label(root, text="endianness:")
combo_endianness = tkinter.ttk.Combobox(root, width=10, state="readonly")
combo_endianness["values"] = ("Big", "Little")
combo_endianness.current(0)
label_endianness2 = tkinter.Label(root, text="endianness is applied to multibyte\nvalues (> 255).", justify="left")

single_int = tkinter.BooleanVar()
single_int.set(False)
checkbox = tkinter.Checkbutton(root, variable=single_int, text="Convert into single integer value\n(except leading / trailing zeros)", justify="left", command=(lambda r=root, le1=label_endianness1, le2=label_endianness2, ce=combo_endianness: single_int_checked(r, le1, le2, ce)))

if single_int_checkbox:
    checkbox.grid(row=1, column=0, padx=5, pady=5, sticky="w", columnspan=2)

    label_endianness1.grid(row=2, column=0, padx=5, pady=5, sticky="w")
    label_endianness1.grid_remove()
    combo_endianness.grid(row=2, column=1, padx=5, pady=5, sticky="w")
    combo_endianness.grid_remove()
    label_endianness2.grid(row=3, column=0, padx=5, pady=5, sticky="w", columnspan=2)
    label_endianness2.grid_remove()

    button = tkinter.Button(root, text="OK", command=(lambda r=root, cd=combo_delimiter, ce=combo_endianness, s=single_int: print_setting(r, cd, ce, s)))
    button.grid(row=4, column=0, padx=5, pady=5, columnspan=2)
    button.focus() # Focus to this widget
elif endianness_menu:
    label_endianness1.grid(row=1, column=0, padx=5, pady=5, sticky="w")
    combo_endianness.grid(row=1, column=1, padx=5, pady=5, sticky="w")
    label_endianness2.grid(row=2, column=0, padx=5, pady=5, sticky="w", columnspan=2)

    button = tkinter.Button(root, text="OK", command=(lambda r=root, cd=combo_delimiter, ce=combo_endianness, s=single_int: print_setting(r, cd, ce, s)))
    button.grid(row=3, column=0, padx=5, pady=5, columnspan=2)
    button.focus() # Focus to this widget
else:
    button = tkinter.Button(root, text="OK", command=(lambda r=root, cd=combo_delimiter, ce=combo_endianness, s=single_int: print_setting(r, cd, ce, s)))
    button.grid(row=0, column=2, padx=5, pady=5)
    button.focus() # Focus to this widget

# Set callback functions
combo_delimiter.bind("<Return>", lambda event, r=root, cd=combo_delimiter, ce=combo_endianness, s=single_int: print_setting(r, cd, ce, s))
combo_endianness.bind("<Return>", lambda event, r=root, cd=combo_delimiter, ce=combo_endianness, s=single_int: print_setting(r, cd, ce, s))
button.bind("<Return>", lambda event, r=root, cd=combo_delimiter, ce=combo_endianness, s=single_int: print_setting(r, cd, ce, s))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry("+%d+%d" % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
