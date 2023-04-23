#
# Disassemble - Disassemble selected region (the whole file if not selected)
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
import tkinter.messagebox

sys.path.append("./lib")
import dialog_base

try:
    import capstone
except ImportError:
    sys.exit(-1) # Capstone is not installed

class DisassembleDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label_arch = tkinter.Label(self.root, text="Architecture:")
        self.label_arch.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_arch = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_arch["values"] = ("x64", "x86", "ARM", "ARM64", "MIPS", "PowerPC", "PowerPC64", "SPARC")
        self.combo_arch.current(0)
        self.combo_arch.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        self.label_arm_mode = tkinter.Label(self.root, text="Mode:")
        self.label_arm_mode.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.label_arm_mode.grid_remove()

        self.combo_arm_mode = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_arm_mode["values"] = ("ARM", "Thumb")
        self.combo_arm_mode.current(0)
        self.combo_arm_mode.grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.combo_arm_mode.grid_remove()

        self.label_mips_mode = tkinter.Label(self.root, text="Mode:")
        self.label_mips_mode.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.label_mips_mode.grid_remove()

        self.combo_mips_mode = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_mips_mode["values"] = ("MIPS32", "MIPS64", "MIPS32R6")
        self.combo_mips_mode.current(0)
        self.combo_mips_mode.grid(row=2, column=2, padx=5, pady=5, sticky="w")
        self.combo_mips_mode.grid_remove()

        self.label_endian = tkinter.Label(self.root, text="Big endian:")
        self.label_endian.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.label_endian.grid_remove()

        self.combo_endian = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_endian["values"] = ("False", "True")
        self.combo_endian.current(0)
        self.combo_endian.grid(row=3, column=2, padx=5, pady=5, sticky="w")
        self.combo_endian.grid_remove()

        self.label_micromips = tkinter.Label(self.root, text="microMIPS:")
        self.label_micromips.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.label_micromips.grid_remove()

        self.combo_micromips = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_micromips["values"] = ("False", "True")
        self.combo_micromips.current(0)
        self.combo_micromips.grid(row=4, column=2, padx=5, pady=5, sticky="w")
        self.combo_micromips.grid_remove()

        self.label_mclass = tkinter.Label(self.root, text="ARM M-class:")
        self.label_mclass.grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.label_mclass.grid_remove()

        self.combo_mclass = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_mclass["values"] = ("False", "True")
        self.combo_mclass.current(0)
        self.combo_mclass.grid(row=5, column=2, padx=5, pady=5, sticky="w")
        self.combo_mclass.grid_remove()

        self.label_v8 = tkinter.Label(self.root, text="ARM v8:")
        self.label_v8.grid(row=6, column=0, padx=5, pady=5, sticky="w")
        self.label_v8.grid_remove()

        self.combo_v8 = tkinter.ttk.Combobox(self.root, state="readonly")
        self.combo_v8["values"] = ("False", "True")
        self.combo_v8.current(0)
        self.combo_v8.grid(row=6, column=2, padx=5, pady=5, sticky="w")
        self.combo_v8.grid_remove()

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.get_selection()))
        self.button.grid(row=7, column=0, padx=5, pady=5, columnspan=3)
        self.button.focus() # Focus to this widget

        # Set callback functions
        self.combo_arch.bind('<<ComboboxSelected>>', lambda event: self.combo_arch_selected())
        self.combo_arm_mode.bind('<<ComboboxSelected>>', lambda event: self.combo_arm_mode_selected())

        for x in (self.combo_arch, self.combo_arm_mode, self.combo_mips_mode, self.combo_endian, self.combo_micromips, self.combo_mclass, self.combo_v8, self.button):
            x.bind("<Return>", lambda event: self.get_selection())

    # Print selected items
    def get_selection(self):
        if self.combo_arch.get() == "x64":
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_64
        elif self.combo_arch.get() == "x86":
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_32
        elif self.combo_arch.get() == "ARM":
            arch = capstone.CS_ARCH_ARM

            if self.combo_arm_mode.get() == "ARM":
                mode = capstone.CS_MODE_ARM
                if self.combo_mclass.get() == "True":
                    mode += capstone.CS_MODE_MCLASS
            else: # Thumb
                mode = capstone.CS_MODE_THUMB

            if self.combo_v8.get() == "True":
                mode += capstone.CS_MODE_V8

            if self.combo_endian.get() == "True":
                mode += capstone.CS_MODE_BIG_ENDIAN
            else:
                mode += capstone.CS_MODE_LITTLE_ENDIAN
        elif self.combo_arch.get() == "ARM64":
            arch = capstone.CS_ARCH_ARM64
            mode = capstone.CS_MODE_ARM

            if self.combo_endian.get() == "True":
                mode += capstone.CS_MODE_BIG_ENDIAN
            else:
                mode += capstone.CS_MODE_LITTLE_ENDIAN
        elif self.combo_arch.get() == "MIPS":
            arch = capstone.CS_ARCH_MIPS

            if self.combo_mips_mode.get() == "MIPS32":
                mode = capstone.CS_MODE_MIPS32
            elif self.combo_mips_mode.get() == "MIPS64":
                mode = capstone.CS_MODE_MIPS64
            elif self.combo_mips_mode.get() == "MIPS32R6":
                mode = capstone.CS_MODE_MIPS32R6

            if self.combo_micromips.get() == "True":
                mode += capstone.CS_MODE_MICRO

            if self.combo_endian.get() == "True":
                mode += capstone.CS_MODE_BIG_ENDIAN
            else:
                mode += capstone.CS_MODE_LITTLE_ENDIAN
        elif self.combo_arch.get() == "PowerPC":
            arch = capstone.CS_ARCH_PPC
            mode = capstone.CS_MODE_32

            if self.combo_endian.get() == "True":
                mode += capstone.CS_MODE_BIG_ENDIAN
            else:
                mode += capstone.CS_MODE_LITTLE_ENDIAN
        elif self.combo_arch.get() == "PowerPC64":
            arch = capstone.CS_ARCH_PPC
            mode = capstone.CS_MODE_64

            if self.combo_endian.get() == "True":
                mode += capstone.CS_MODE_BIG_ENDIAN
            else:
                mode += capstone.CS_MODE_LITTLE_ENDIAN
        elif self.combo_arch.get() == "SPARC":
            arch = capstone.CS_ARCH_SPARC
            mode = capstone.CS_MODE_BIG_ENDIAN

        print("%s\t%s" % (str(arch), str(mode))) # These values will be passed to disassemble.py
        self.show_disassembly_setting(arch, mode) # Pass message of disassembly settings via stderr
        self.root.quit()

    def show_disassembly_setting(self, arch, mode):
        print("Disassembly settings:", file=sys.stderr)
        if arch == capstone.CS_ARCH_X86:
            if mode & capstone.CS_MODE_32:
                print("  Architecture: x86", file=sys.stderr)
            elif mode & capstone.CS_MODE_64:
                print("  Architecture: x64", file=sys.stderr)
        elif arch == capstone.CS_ARCH_ARM:
            print("  Architecture: ARM", file=sys.stderr)

            if mode & capstone.CS_MODE_THUMB:
                print("  Mode: Thumb", file=sys.stderr)
            else: # capstone.CS_MODE_ARM (0)
                print("  Mode: ARM", file=sys.stderr)

            if mode & capstone.CS_MODE_BIG_ENDIAN:
                print("  Big endian: true", file=sys.stderr)
            else:
                print("  Big endian: false", file=sys.stderr)

            if not mode & capstone.CS_MODE_THUMB: # capstone.CS_MODE_ARM (0)
                if mode & capstone.CS_MODE_MCLASS:
                    print("  ARM M-class: true", file=sys.stderr)
                else:
                    print("  ARM M-class: false", file=sys.stderr)

            if mode & capstone.CS_MODE_V8:
                print("  ARM v8: true", file=sys.stderr)
            else:
                print("  ARM v8: false", file=sys.stderr)
        elif arch == capstone.CS_ARCH_ARM64:
            print("  Architecture: ARM64", file=sys.stderr)

            if mode & capstone.CS_MODE_BIG_ENDIAN:
                print("  Big endian: true", file=sys.stderr)
            else:
                print("  Big endian: false", file=sys.stderr)
        elif arch == capstone.CS_ARCH_MIPS:
            print("  Architecture: MIPS", file=sys.stderr)

            if mode & capstone.CS_MODE_MIPS32:
                print("  Mode: MIPS32", file=sys.stderr)
            elif mode & capstone.CS_MODE_MIPS64:
                print("  Mode: MIPS64", file=sys.stderr)
            elif mode & capstone.CS_MODE_MIPS32R6:
                print("  Mode: MIPS32R6", file=sys.stderr)

            if mode & capstone.CS_MODE_BIG_ENDIAN:
                print("  Big endian: true", file=sys.stderr)
            else:
                print("  Big endian: false", file=sys.stderr)

            if mode & capstone.CS_MODE_MICRO:
                print("  microMIPS: true", file=sys.stderr)
            else:
                print("  microMIPS: false", file=sys.stderr)
        elif arch == capstone.CS_ARCH_PPC:
            if mode & capstone.CS_MODE_32:
                print("  Architecture: PowerPC", file=sys.stderr)
            elif mode & capstone.CS_MODE_64:
                print("  Architecture: PowerPC64", file=sys.stderr)

            if mode & capstone.CS_MODE_BIG_ENDIAN:
                print("  Big endian: true", file=sys.stderr)
            else:
                print("  Big endian: false", file=sys.stderr)
        elif arch == capstone.CS_ARCH_SPARC:
                print("  Architecture: SPARC", file=sys.stderr)

    def combo_arch_selected(self):
        # Hide / show labels and comboboxes
        if self.combo_arch.get() in ["x64", "x86", "SPARC"]:
            self.label_arm_mode.grid_remove()
            self.combo_arm_mode.grid_remove()
            self.label_mips_mode.grid_remove()
            self.combo_mips_mode.grid_remove()
            self.label_endian.grid_remove()
            self.combo_endian.grid_remove()
            self.label_micromips.grid_remove()
            self.combo_micromips.grid_remove()
            self.label_mclass.grid_remove()
            self.combo_mclass.grid_remove()
            self.label_v8.grid_remove()
            self.combo_v8.grid_remove()
        elif self.combo_arch.get() == "ARM":
            self.label_arm_mode.grid()
            self.combo_arm_mode.grid()
            self.label_mips_mode.grid_remove()
            self.combo_mips_mode.grid_remove()
            self.label_endian.grid()
            self.combo_endian.grid()
            self.combo_endian.current(0) # set default to little endian
            self.label_micromips.grid_remove()
            self.combo_micromips.grid_remove()
            self.label_mclass.grid()
            self.combo_mclass.grid()
            self.label_v8.grid()
            self.combo_v8.grid()
        elif self.combo_arch.get() == "ARM64":
            self.label_arm_mode.grid_remove()
            self.combo_arm_mode.grid_remove()
            self.label_mips_mode.grid_remove()
            self.combo_mips_mode.grid_remove()
            self.label_endian.grid()
            self.combo_endian.grid()
            self.combo_endian.current(0) # set default to little endian
            self.label_micromips.grid_remove()
            self.combo_micromips.grid_remove()
            self.label_mclass.grid_remove()
            self.combo_mclass.grid_remove()
            self.label_v8.grid_remove()
            self.combo_v8.grid_remove()
        elif self.combo_arch.get() == "MIPS":
            self.label_arm_mode.grid_remove()
            self.combo_arm_mode.grid_remove()
            self.label_mips_mode.grid()
            self.combo_mips_mode.grid()
            self.label_endian.grid()
            self.combo_endian.grid()
            self.combo_endian.current(0) # set default to little endian
            self.label_micromips.grid()
            self.combo_micromips.grid()
            self.label_mclass.grid_remove()
            self.combo_mclass.grid_remove()
            self.label_v8.grid_remove()
            self.combo_v8.grid_remove()
        elif self.combo_arch.get() in ["PowerPC", "PowerPC64"]:
            self.label_arm_mode.grid_remove()
            self.combo_arm_mode.grid_remove()
            self.label_mips_mode.grid_remove()
            self.combo_mips_mode.grid_remove()
            self.label_endian.grid()
            self.combo_endian.grid()
            self.combo_endian.current(1) # set default to big endian
            self.label_micromips.grid_remove()
            self.combo_micromips.grid_remove()
            self.label_mclass.grid_remove()
            self.combo_mclass.grid_remove()
            self.label_v8.grid_remove()
            self.combo_v8.grid_remove()

    def combo_arm_mode_selected(self):
        # Hide / show labels and comboboxes
        if self.combo_arm_mode.get() == "Thumb":
            self.label_mclass.grid_remove()
            self.combo_mclass.grid_remove()
        else: # ARM
            self.label_mclass.grid()
            self.combo_mclass.grid()

if __name__ == "__main__":
    dialog = DisassembleDialog(title="Disassemble")
    dialog.show()
