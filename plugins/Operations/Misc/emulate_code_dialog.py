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

import re
import sys
import tkinter
import tkinter.ttk
import tkinter.messagebox

sys.path.append("./Misc")
import emulate_code_qiling

# Print selected items
def get_selection(r, cf, ct, co, ca, ce, ea, bt, t):
    if cf.get() == "Qiling Framework":
        rootfs_base = "Misc\\qiling-master\\examples\\rootfs"
        arch = ca.get().lower()
        if arch == "x64":
            arch = "x8664"
        big_endian = ce.get()
        if big_endian == "True":
            big_endian = True
        else:
            big_endian = False
        path = str(emulate_code_qiling.rootfs_path(rootfs_base, arch, co.get().lower(), big_endian))
        print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (cf.get(), ct.get(), co.get(), ca.get().lower(), ce.get(), ea.get(), bt.get(), t.get(), path), end="")
    else:
        print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (cf.get(), ct.get(), co.get(), ca.get().lower(), ce.get(), ea.get(), bt.get(), t.get(), "None"), end="")

    root.quit()

def combo_framework_selected(r, cf, co, ca, le, ce, lt, ct):
    # Hide / show endian combobox
    if cf.get() == "Speakeasy":
        co.current(0)
        co.configure(state="disabled")
        ca.configure(values=("x64", "x86"))
        ca.current(0)
        le.grid_remove()
        ce.grid_remove()
        lt.grid_remove()
        ct.grid_remove()
    else: # Qiling Framework
        co.configure(state="readonly")
        co.current(0)
        ca.configure(values=("x64", "x86", "ARM", "ARM64", "MIPS"))
        ca.current(0)
        lt.grid()
        ct.grid()

def combo_arch_selected(r, ca, le, ce):
    # Hide / show endian combobox
    if ca.get() in ("ARM", "ARM64", "MIPS"):
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

def timeout_changed(*args):
    if not re.match("^-?([0-9])+$", timeout.get()):
        timeout.set("60")
    elif int(timeout.get()) < 0:
        timeout.set("0")

# Create selection dialog
root = tkinter.Tk()
root.title("Emulate code")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_framework = tkinter.Label(root, text="Emulation framework:")
label_framework.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_framework = tkinter.ttk.Combobox(root, state="readonly")
combo_framework["values"] = ("Qiling Framework", "Speakeasy")
combo_framework.current(0)
combo_framework.grid(row=0, column=2, padx=5, pady=5, sticky="w")

label_type = tkinter.Label(root, text="File type:")
label_type.grid(row=1, column=0, padx=5, pady=5, sticky="w")

combo_type = tkinter.ttk.Combobox(root, state="readonly")
combo_type["values"] = ("Executable", "Shellcode")
combo_type.current(0)
combo_type.grid(row=1, column=2, padx=5, pady=5, sticky="w")

label_os = tkinter.Label(root, text="OS:")
label_os.grid(row=2, column=0, padx=5, pady=5, sticky="w")

combo_os = tkinter.ttk.Combobox(root, state="readonly")
combo_os["values"] = ("Windows", "Linux") # Currently macOS, UEFI and FreeBSD are excluded
combo_os.current(0)
combo_os.grid(row=2, column=2, padx=5, pady=5, sticky="w")

label_arch = tkinter.Label(root, text="Architecture:")
label_arch.grid(row=3, column=0, padx=5, pady=5, sticky="w")

combo_arch = tkinter.ttk.Combobox(root, state="readonly")
combo_arch["values"] = ("x64", "x86", "ARM", "ARM64", "MIPS")
combo_arch.current(0)
combo_arch.grid(row=3, column=2, padx=5, pady=5, sticky="w")

label_endian = tkinter.Label(root, text="Big endian:")
label_endian.grid(row=4, column=0, padx=5, pady=5, sticky="w")
label_endian.grid_remove()

combo_endian = tkinter.ttk.Combobox(root, state="readonly")
combo_endian["values"] = ("False", "True")
combo_endian.current(0)
combo_endian.grid(row=4, column=2, padx=5, pady=5, sticky="w")
combo_endian.grid_remove()

label_args = tkinter.Label(root, text="Command line arguments:")
label_args.grid(row=5, column=0, padx=5, pady=5, sticky="w")

entry_args = tkinter.Entry(width=24)
entry_args.grid(row=5, column=2, padx=5, pady=5, sticky="w")

label_thread = tkinter.Label(root, text="Multithread:")
label_thread.grid(row=6, column=0, padx=5, pady=5, sticky="w")
bool_thread = tkinter.BooleanVar()
bool_thread.set(False)
check_thread = tkinter.Checkbutton(root, variable=bool_thread, text="", onvalue=True, offvalue=False)
check_thread.grid(row=6, column=2, padx=5, pady=5, sticky="w")

label_timeout = tkinter.Label(root, text="Emulation timeout\n(seconds, 0 = no timeout):", justify="left")
label_timeout.grid(row=7, column=0, padx=5, pady=5, sticky="w")
timeout = tkinter.StringVar()
timeout.set("60")
timeout.trace("w", timeout_changed)
spin_timeout = tkinter.Spinbox(root, textvariable=timeout, width=4, from_=0, to=10000)
spin_timeout.grid(row=7, column=2, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda r=root, cf=combo_framework, ct=combo_type, co=combo_os, ca=combo_arch, ce=combo_endian, ea=entry_args, bt=bool_thread, t=timeout: get_selection(r, cf, ct, co, ca, ce, ea, bt, t)))
button.grid(row=8, column=0, padx=5, pady=5, columnspan=3)
button.focus() # Focus to this widget

# Set callback functions
combo_framework.bind('<<ComboboxSelected>>', lambda event, r=root, cf=combo_framework, co=combo_os, ca=combo_arch, le=label_endian, ce=combo_endian, lt=label_thread, ct=check_thread: combo_framework_selected(r, cf, co, ca, le, ce, lt, ct))
combo_arch.bind('<<ComboboxSelected>>', lambda event, r=root, ca=combo_arch, le=label_endian, ce=combo_endian: combo_arch_selected(r, ca, le, ce))
combo_type.bind('<<ComboboxSelected>>', lambda event, r=root, ct=combo_type, la=label_args, ea=entry_args: combo_type_selected(r, ct, la, ea))

for x in (combo_framework, combo_type, combo_os, combo_arch, combo_endian, entry_args, check_thread, spin_timeout, button):
    x.bind("<Return>", lambda event, r=root, cf=combo_framework, ct=combo_type, co=combo_os, ca=combo_arch, ce=combo_endian, ea=entry_args, bt=bool_thread, t=timeout: get_selection(r, cf, ct, co, ca, ce, ea, bt, t))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
