#
# Unit setting dialog for "Change endianness" plugin
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

import tkinter
import tkinter.ttk

# Print setting to stdout
def print_setting(r, cu):
    print("%s" % cu.get())
    root.quit()

# Create setting dialog
root = tkinter.Tk()
root.title("Change endianness")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))
label_unit = tkinter.Label(root, text="Unit to change:")
label_unit.grid(row=0, column=0, padx=5, pady=5, sticky="w")
combo_unit = tkinter.ttk.Combobox(root, width=18, state="readonly")
combo_unit["values"] = ("WORD (2 bytes)", "DWORD (4 bytes)", "QWORD (8 bytes)")
combo_unit.current(0)
combo_unit.grid(row=0, column=1, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda r=root, cu=combo_unit: print_setting(r, cu)))
button.grid(row=1, column=0, padx=5, pady=5, columnspan=2)
button.focus() # Focus to this widget

# Set callback functions
button.bind("<Return>", lambda event, r=root, cu=combo_unit: print_setting(r, cu))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry("+%d+%d" % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
