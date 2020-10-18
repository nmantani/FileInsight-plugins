#
# Emulate code - Emulate selected region as an executable or shellcode
# with Qiling Framework (the whole file if not selected)
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
import time
import tkinter
import tkinter.ttk
import tkinter.messagebox

# Print selected items
def get_selection(r, ct, co, ca, ce, ea):
    print("%s\t%s\t%s\t%s\t%s" % (ct.get(), co.get(), ca.get(), ce.get(), ea.get()))
    r.quit()

def combo_arch_selected(r, ca, le, ce):
    # Hide / show endian combobox
    if ca.get() in ("arm", "arm64", "mips"):
        le.grid()
        ce.grid()
    else:
        ce.current(0)
        le.grid_remove()
        ce.grid_remove()

def combo_type_selected(r, ct, la, ea):
    # Hide / show arguments entry
    if ct.get() == "Executable":
        la.grid()
        ea.grid()
    else:
        la.grid_remove()
        ea.grid_remove()

# Create selection dialog
root = tkinter.Tk()
root.title("Emulate code")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_type = tkinter.Label(root, text="File type:")
label_type.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_type = tkinter.ttk.Combobox(root, state="readonly")
combo_type["values"] = ("Executable", "Shellcode")
combo_type.current(0)
combo_type.grid(row=0, column=2, padx=5, pady=5, sticky="w")

label_os = tkinter.Label(root, text="OS:")
label_os.grid(row=1, column=0, padx=5, pady=5, sticky="w")

combo_os = tkinter.ttk.Combobox(root, state="readonly")
combo_os["values"] = ("Windows", "Linux") # Currently macOS, UEFI and FreeBSD are excluded
combo_os.current(0)
combo_os.grid(row=1, column=2, padx=5, pady=5, sticky="w")

label_arch = tkinter.Label(root, text="Architecture:")
label_arch.grid(row=2, column=0, padx=5, pady=5, sticky="w")

combo_arch = tkinter.ttk.Combobox(root, state="readonly")
combo_arch["values"] = ("x64", "x86", "arm", "arm64", "mips")
combo_arch.current(0)
combo_arch.grid(row=2, column=2, padx=5, pady=5, sticky="w")

label_endian = tkinter.Label(root, text="Big endian:")
label_endian.grid(row=3, column=0, padx=5, pady=5, sticky="w")
label_endian.grid_remove()

combo_endian = tkinter.ttk.Combobox(root, state="readonly")
combo_endian["values"] = ("False", "True")
combo_endian.current(0)
combo_endian.grid(row=3, column=2, padx=5, pady=5, sticky="w")
combo_endian.grid_remove()

label_args = tkinter.Label(root, text="Command line arguments:")
label_args.grid(row=4, column=0, padx=5, pady=5, sticky="w")

entry_args = tkinter.Entry(width=24)
entry_args.grid(row=4, column=2, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda r=root, ct=combo_type, co=combo_os, ca=combo_arch, ce=combo_endian, ea=entry_args: get_selection(r, ct, co, ca, ce, ea)))
button.grid(row=5, column=0, padx=5, pady=5, columnspan=3)

# Set callback functions
combo_arch.bind('<<ComboboxSelected>>', (lambda r=root, ca=combo_arch, le=label_endian, ce=combo_endian: combo_arch_selected(r, ca, le, ce)))
combo_type.bind('<<ComboboxSelected>>', (lambda r=root, ct=combo_type, la=label_args, ea=entry_args: combo_type_selected(r, ct, la, ea)))

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/2.5), (h/2.5)))

root.mainloop()
