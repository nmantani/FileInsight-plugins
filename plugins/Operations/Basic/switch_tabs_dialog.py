#
# Switch tabs - Switch file tabs with a listbox
#
# Copyright (c) 2022, Nobutaka Mantani
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
import tkinter.messagebox

# Print selected items
def get_selection(r, lb):
    print("%d" % lb.curselection())
    root.quit()

# Read list of tabs from stdin
tabs = sys.stdin.readlines()

max_len = 0
for t in tabs:
    if len(t) > max_len:
        max_len = len(t)

# Create a dialog
root = tkinter.Tk()
root.title("Switch tabs")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

strvar_tabs = tkinter.StringVar(value=tabs)
listbox = tkinter.Listbox(root, selectmode="single", listvariable=strvar_tabs, width=max_len+10, height=16)
scrollbar = tkinter.ttk.Scrollbar(root, orient='vertical', command=listbox.yview)
listbox["yscrollcommand"] = scrollbar.set
listbox.grid(row=0, column=0, padx=5, pady=5)
scrollbar.grid(row=0, column=1, sticky=(tkinter.N, tkinter.S))
listbox.selection_set(0)

button = tkinter.Button(root, text="OK", command=(lambda r=root, lb=listbox: get_selection(r, lb)))
button.grid(row=1, column=0, padx=5, pady=5)
button.focus() # Focus to this widget

# Set callback functions
for x in (listbox, button):
    x.bind("<Return>", lambda event, r=root, lb=listbox: get_selection(r, lb))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
