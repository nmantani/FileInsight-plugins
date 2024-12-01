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

sys.path.append("./lib")
import dialog_base

class EmulateCodeDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label_framework = tkinter.Label(self.root, text="Emulation framework:")
        self.label_framework.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_framework = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_framework["values"] = ("Qiling Framework", "Speakeasy")
        self.combo_framework.current(0)
        self.combo_framework.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        self.label_type = tkinter.Label(self.root, text="File type:")
        self.label_type.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.combo_type = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_type["values"] = ("Executable", "Shellcode")
        self.combo_type.current(0)
        self.combo_type.grid(row=1, column=2, padx=5, pady=5, sticky="w")

        self.label_os = tkinter.Label(self.root, text="OS:")
        self.label_os.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.combo_os = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_os["values"] = ("Windows", "Linux") # Currently macOS, UEFI and FreeBSD are excluded
        self.combo_os.current(0)
        self.combo_os.grid(row=2, column=2, padx=5, pady=5, sticky="w")

        self.label_arch = tkinter.Label(self.root, text="Architecture:")
        self.label_arch.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.combo_arch = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_arch["values"] = ("x64", "x86", "ARM", "ARM64", "MIPS", "RISC-V32", "RISC-V64")
        self.combo_arch.current(0)
        self.combo_arch.grid(row=3, column=2, padx=5, pady=5, sticky="w")

        self.label_endian = tkinter.Label(self.root, text="Big endian:")
        self.label_endian.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.label_endian.grid_remove()

        self.combo_endian = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_endian["values"] = ("False", "True")
        self.combo_endian.current(0)
        self.combo_endian.grid(row=4, column=2, padx=5, pady=5, sticky="w")
        self.combo_endian.grid_remove()

        self.label_args = tkinter.Label(self.root, text="Command line arguments:")
        self.label_args.grid(row=5, column=0, padx=5, pady=5, sticky="w")

        self.entry_args = tkinter.Entry(width=24)
        self.entry_args.grid(row=5, column=2, padx=5, pady=5, sticky="w")

        self.label_thread = tkinter.Label(self.root, text="Multithread:")
        self.label_thread.grid(row=6, column=0, padx=5, pady=5, sticky="w")
        self.bool_thread = tkinter.BooleanVar()
        self.bool_thread.set(False)
        self.check_thread = tkinter.Checkbutton(self.root, variable=self.bool_thread, text="", onvalue=True, offvalue=False)
        self.check_thread.grid(row=6, column=2, padx=5, pady=5, sticky="w")

        self.label_timeout = tkinter.Label(self.root, text="Emulation timeout\n(seconds, 0 = no timeout):", justify="left")
        self.label_timeout.grid(row=7, column=0, padx=5, pady=5, sticky="w")
        self.timeout = tkinter.StringVar()
        self.timeout.set("60")
        self.timeout.trace_add("write", self.timeout_changed)
        self.spin_timeout = tkinter.Spinbox(self.root, textvariable=self.timeout, width=4, from_=0, to=10000)
        self.spin_timeout.grid(row=7, column=2, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.get_selection()))
        self.button.grid(row=8, column=0, padx=5, pady=5, columnspan=3)
        self.button.focus() # Focus to this widget

        # Set callback functions
        self.combo_framework.bind('<<ComboboxSelected>>', lambda event: self.combo_framework_selected())
        self.combo_arch.bind('<<ComboboxSelected>>', lambda event: self.combo_arch_selected())
        self.combo_type.bind('<<ComboboxSelected>>', lambda event: self.combo_type_selected())

        for x in (self.combo_framework, self.combo_type, self.combo_os, self.combo_arch, self.combo_endian, self.entry_args, self.check_thread, self.spin_timeout, self.button):
            x.bind("<Return>", lambda event: self.get_selection())

    # Print selected items
    def get_selection(self):
        if self.combo_framework.get() == "Qiling Framework":
            rootfs_base = "Misc\\qiling-master\\examples\\rootfs"
            arch = self.combo_arch.get().lower()
            if arch == "x64":
                arch = "x8664"
            elif arch == "RISC-V32":
                arch = "riscv32"
            elif arch == "RISC-V64":
                arch = "riscv64"
            big_endian = self.combo_endian.get()
            if big_endian == "True":
                big_endian = True
            else:
                big_endian = False
            path = str(emulate_code_qiling.rootfs_path(rootfs_base, arch.lower(), self.combo_os.get().lower(), big_endian))
            print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (self.combo_framework.get(), self.combo_type.get(), self.combo_os.get(), self.combo_arch.get(), self.combo_endian.get(), self.entry_args.get(), self.bool_thread.get(), self.timeout.get(), path), end="")
        else:
            print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (self.combo_framework.get(), self.combo_type.get(), self.combo_os.get(), self.combo_arch.get().lower(), self.combo_endian.get(), self.entry_args.get(), self.bool_thread.get(), self.timeout.get(), "None"), end="")

        self.root.quit()

    def combo_framework_selected(self):
        # Hide / show endian combobox
        if self.combo_framework.get() == "Speakeasy":
            self.combo_os.current(0)
            self.combo_os.configure(state="disabled")
            self.combo_arch.configure(values=("x64", "x86"))
            self.combo_arch.current(0)
            self.label_endian.grid_remove()
            self.combo_endian.grid_remove()
            self.label_thread.grid_remove()
            self.check_thread.grid_remove()
        else: # Qiling Framework
            self.combo_os.configure(state="readonly")
            self.combo_os.current(0)
            self.combo_arch.configure(values=("x64", "x86", "ARM", "ARM64", "MIPS", "RISC-V32", "RISC-V64"))
            self.combo_arch.current(0)
            self.label_thread.grid()
            self.check_thread.grid()

    def combo_arch_selected(self):
        # Hide / show endian combobox
        if self.combo_arch.get() in ("ARM", "ARM64", "MIPS"):
            self.label_endian.grid()
            self.combo_endian.grid()
        else:
            self.combo_endian.current(0)
            self.label_endian.grid_remove()
            self.combo_endian.grid_remove()

    def combo_type_selected(self):
        # Hide / show arguments entry
        if self.combo_type.get() == "Executable":
            self.label_args.grid()
            self.entry_args.grid()
        else:
            self.label_args.grid_remove()
            self.entry_args.grid_remove()

    def timeout_changed(self, *args):
        if not re.match("^-?([0-9])+$", self.timeout.get()):
            self.timeout.set("60")
        elif int(self.timeout.get()) < 0:
            self.timeout.set("0")

if __name__ == "__main__":
    dialog = EmulateCodeDialog(title="Emulate code")
    dialog.show()
