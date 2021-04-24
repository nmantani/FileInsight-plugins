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

import re
import tkinter
import tkinter.ttk

# Print delimiter setting to stdout
def print_setting(r, c):
    print(c.get())
    exit(0)

# Create input dialog
root = tkinter.Tk()
root.title('Delimiter setting')
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))
label = tkinter.Label(root, text='Delimiter:')
label.grid(row=0, column=0, padx=5, pady=5)
combo_delimiter = tkinter.ttk.Combobox(root, width=10, state="readonly")
combo_delimiter["values"] = ("Space", "Comma", "Semi-colon", "Colon", "Tab", "LF", "CRLF")
combo_delimiter.current(0)
combo_delimiter.grid(row=0, column=1, padx=5, pady=5, sticky="w")
button = tkinter.Button(root, text='OK', command=(lambda r=root, c=combo_delimiter: print_setting(r, c)))
button.grid(row=0, column=2, padx=5, pady=5)
button.focus() # Focus to this widget

# Set callback functions
combo_delimiter.bind("<Return>", lambda r=root, c=combo_delimiter: print_setting(r, c))
button.bind("<Return>", lambda r=root, c=combo_delimiter: print_setting(r, c))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
