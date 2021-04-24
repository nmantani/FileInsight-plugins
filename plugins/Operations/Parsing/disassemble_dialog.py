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
import time
import tkinter
import tkinter.ttk
import tkinter.messagebox

try:
    import capstone
except ImportError:
    sys.exit(-1) # Capstone is not installed

# Print selected items
def get_selection(r, w):
    if w["combo_arch"].get() == "x64":
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64
    elif w["combo_arch"].get() == "x86":
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_32
    elif w["combo_arch"].get() == "ARM":
        arch = capstone.CS_ARCH_ARM

        if w["combo_arm_mode"].get() == "ARM":
            mode = capstone.CS_MODE_ARM
            if w["combo_mclass"].get() == "True":
                mode += capstone.CS_MODE_MCLASS
        else: # Thumb
            mode = capstone.CS_MODE_THUMB

        if w["combo_v8"].get() == "True":
            mode += capstone.CS_MODE_V8

        if w["combo_endian"].get() == "True":
            mode += capstone.CS_MODE_BIG_ENDIAN
        else:
            mode += capstone.CS_MODE_LITTLE_ENDIAN
    elif w["combo_arch"].get() == "ARM64":
        arch = capstone.CS_ARCH_ARM64
        mode = capstone.CS_MODE_ARM

        if w["combo_endian"].get() == "True":
            mode += capstone.CS_MODE_BIG_ENDIAN
        else:
            mode += capstone.CS_MODE_LITTLE_ENDIAN
    elif w["combo_arch"].get() == "MIPS":
        arch = capstone.CS_ARCH_MIPS

        if w["combo_mips_mode"].get() == "MIPS32":
            mode = capstone.CS_MODE_MIPS32
        elif w["combo_mips_mode"].get() == "MIPS64":
            mode = capstone.CS_MODE_MIPS64
        elif w["combo_mips_mode"].get() == "MIPS32R6":
            mode = capstone.CS_MODE_MIPS32R6

        if w["combo_micromips"].get() == "True":
            mode += capstone.CS_MODE_MICRO

        if w["combo_endian"].get() == "True":
            mode += capstone.CS_MODE_BIG_ENDIAN
        else:
            mode += capstone.CS_MODE_LITTLE_ENDIAN
    elif w["combo_arch"].get() == "PowerPC":
        arch = capstone.CS_ARCH_PPC
        mode = capstone.CS_MODE_32

        if w["combo_endian"].get() == "True":
            mode += capstone.CS_MODE_BIG_ENDIAN
        else:
            mode += capstone.CS_MODE_LITTLE_ENDIAN
    elif w["combo_arch"].get() == "PowerPC64":
        arch = capstone.CS_ARCH_PPC
        mode = capstone.CS_MODE_64

        if w["combo_endian"].get() == "True":
            mode += capstone.CS_MODE_BIG_ENDIAN
        else:
            mode += capstone.CS_MODE_LITTLE_ENDIAN
    elif w["combo_arch"].get() == "SPARC":
        arch = capstone.CS_ARCH_SPARC
        mode = capstone.CS_MODE_BIG_ENDIAN

    print("%s\t%s" % (str(arch), str(mode))) # These values will be passed to disassemble.py
    show_disassembly_setting(arch, mode) # Pass message of disassembly settings via stderr
    exit(0)

def show_disassembly_setting(arch, mode):
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

def combo_arch_selected(r, w):
    # Hide / show labels and comboboxes
    if w["combo_arch"].get() in ["x64", "x86", "SPARC"]:
        w["label_arm_mode"].grid_remove()
        w["combo_arm_mode"].grid_remove()
        w["label_mips_mode"].grid_remove()
        w["combo_mips_mode"].grid_remove()
        w["label_endian"].grid_remove()
        w["combo_endian"].grid_remove()
        w["label_micromips"].grid_remove()
        w["combo_micromips"].grid_remove()
        w["label_mclass"].grid_remove()
        w["combo_mclass"].grid_remove()
        w["label_v8"].grid_remove()
        w["combo_v8"].grid_remove()
    elif w["combo_arch"].get() == "ARM":
        w["label_arm_mode"].grid()
        w["combo_arm_mode"].grid()
        w["label_mips_mode"].grid_remove()
        w["combo_mips_mode"].grid_remove()
        w["label_endian"].grid()
        w["combo_endian"].grid()
        w["combo_endian"].current(0) # set default to little endian
        w["label_micromips"].grid_remove()
        w["combo_micromips"].grid_remove()
        w["label_mclass"].grid()
        w["combo_mclass"].grid()
        w["label_v8"].grid()
        w["combo_v8"].grid()
    elif w["combo_arch"].get() == "ARM64":
        w["label_arm_mode"].grid_remove()
        w["combo_arm_mode"].grid_remove()
        w["label_mips_mode"].grid_remove()
        w["combo_mips_mode"].grid_remove()
        w["label_endian"].grid()
        w["combo_endian"].grid()
        w["combo_endian"].current(0) # set default to little endian
        w["label_micromips"].grid_remove()
        w["combo_micromips"].grid_remove()
        w["label_mclass"].grid_remove()
        w["combo_mclass"].grid_remove()
        w["label_v8"].grid_remove()
        w["combo_v8"].grid_remove()
    elif w["combo_arch"].get() == "MIPS":
        w["label_arm_mode"].grid_remove()
        w["combo_arm_mode"].grid_remove()
        w["label_mips_mode"].grid()
        w["combo_mips_mode"].grid()
        w["label_endian"].grid()
        w["combo_endian"].grid()
        w["combo_endian"].current(0) # set default to little endian
        w["label_micromips"].grid()
        w["combo_micromips"].grid()
        w["label_mclass"].grid_remove()
        w["combo_mclass"].grid_remove()
        w["label_v8"].grid_remove()
        w["combo_v8"].grid_remove()
    elif w["combo_arch"].get() in ["PowerPC", "PowerPC64"]:
        w["label_arm_mode"].grid_remove()
        w["combo_arm_mode"].grid_remove()
        w["label_mips_mode"].grid_remove()
        w["combo_mips_mode"].grid_remove()
        w["label_endian"].grid()
        w["combo_endian"].grid()
        w["combo_endian"].current(1) # set default to big endian
        w["label_micromips"].grid_remove()
        w["combo_micromips"].grid_remove()
        w["label_mclass"].grid_remove()
        w["combo_mclass"].grid_remove()
        w["label_v8"].grid_remove()
        w["combo_v8"].grid_remove()

def combo_arm_mode_selected(r, w):
    # Hide / show labels and comboboxes
    if w["combo_arm_mode"].get() == "Thumb":
        w["label_mclass"].grid_remove()
        w["combo_mclass"].grid_remove()
    else: # ARM
        w["label_mclass"].grid()
        w["combo_mclass"].grid()

# Create selection dialog
root = tkinter.Tk()
root.title("Disassemble")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

widgets = {}

label_arch = tkinter.Label(root, text="Architecture:")
label_arch.grid(row=0, column=0, padx=5, pady=5, sticky="w")
widgets["label_arch"] = label_arch

combo_arch = tkinter.ttk.Combobox(root, state="readonly")
combo_arch["values"] = ("x64", "x86", "ARM", "ARM64", "MIPS", "PowerPC", "PowerPC64", "SPARC")
combo_arch.current(0)
combo_arch.grid(row=0, column=2, padx=5, pady=5, sticky="w")
widgets["combo_arch"] = combo_arch

label_arm_mode = tkinter.Label(root, text="Mode:")
label_arm_mode.grid(row=1, column=0, padx=5, pady=5, sticky="w")
label_arm_mode.grid_remove()
widgets["label_arm_mode"] = label_arm_mode

combo_arm_mode = tkinter.ttk.Combobox(root, state="readonly")
combo_arm_mode["values"] = ("ARM", "Thumb")
combo_arm_mode.current(0)
combo_arm_mode.grid(row=1, column=2, padx=5, pady=5, sticky="w")
combo_arm_mode.grid_remove()
widgets["combo_arm_mode"] = combo_arm_mode

label_mips_mode = tkinter.Label(root, text="Mode:")
label_mips_mode.grid(row=2, column=0, padx=5, pady=5, sticky="w")
label_mips_mode.grid_remove()
widgets["label_mips_mode"] = label_mips_mode

combo_mips_mode = tkinter.ttk.Combobox(root, state="readonly")
combo_mips_mode["values"] = ("MIPS32", "MIPS64", "MIPS32R6")
combo_mips_mode.current(0)
combo_mips_mode.grid(row=2, column=2, padx=5, pady=5, sticky="w")
combo_mips_mode.grid_remove()
widgets["combo_mips_mode"] = combo_mips_mode

label_endian = tkinter.Label(root, text="Big endian:")
label_endian.grid(row=3, column=0, padx=5, pady=5, sticky="w")
label_endian.grid_remove()
widgets["label_endian"] = label_endian

combo_endian = tkinter.ttk.Combobox(root, state="readonly")
combo_endian["values"] = ("False", "True")
combo_endian.current(0)
combo_endian.grid(row=3, column=2, padx=5, pady=5, sticky="w")
combo_endian.grid_remove()
widgets["combo_endian"] = combo_endian

label_micromips = tkinter.Label(root, text="microMIPS:")
label_micromips.grid(row=4, column=0, padx=5, pady=5, sticky="w")
label_micromips.grid_remove()
widgets["label_micromips"] = label_micromips

combo_micromips = tkinter.ttk.Combobox(root, state="readonly")
combo_micromips["values"] = ("False", "True")
combo_micromips.current(0)
combo_micromips.grid(row=4, column=2, padx=5, pady=5, sticky="w")
combo_micromips.grid_remove()
widgets["combo_micromips"] = combo_micromips

label_mclass = tkinter.Label(root, text="ARM M-class:")
label_mclass.grid(row=5, column=0, padx=5, pady=5, sticky="w")
label_mclass.grid_remove()
widgets["label_mclass"] = label_mclass

combo_mclass = tkinter.ttk.Combobox(root, state="readonly")
combo_mclass["values"] = ("False", "True")
combo_mclass.current(0)
combo_mclass.grid(row=5, column=2, padx=5, pady=5, sticky="w")
combo_mclass.grid_remove()
widgets["combo_mclass"] = combo_mclass

label_v8 = tkinter.Label(root, text="ARM v8:")
label_v8.grid(row=6, column=0, padx=5, pady=5, sticky="w")
label_v8.grid_remove()
widgets["label_v8"] = label_v8

combo_v8 = tkinter.ttk.Combobox(root, state="readonly")
combo_v8["values"] = ("False", "True")
combo_v8.current(0)
combo_v8.grid(row=6, column=2, padx=5, pady=5, sticky="w")
combo_v8.grid_remove()
widgets["combo_v8"] = combo_v8

button = tkinter.Button(root, text="OK", command=(lambda r=root, w=widgets: get_selection(r, w)))
button.grid(row=7, column=0, padx=5, pady=5, columnspan=3)
button.focus() # Focus to this widget

# Set callback functions
combo_arch.bind('<<ComboboxSelected>>', (lambda r=root, w=widgets: combo_arch_selected(r, w)))
combo_arm_mode.bind('<<ComboboxSelected>>', (lambda r=root, w=widgets: combo_arm_mode_selected(r, w)))

for x in (combo_arch, combo_arm_mode, combo_mips_mode, combo_endian, combo_micromips, combo_mclass, combo_v8, button):
    x.bind("<Return>", lambda r=root, w=widgets: get_selection(r, w))

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
