#
# QuickLZ compress - Compress selected region with QuickLZ compression library
#
# Copyright (c) 2021, Nobutaka Mantani
# All rights reserved.
#
# This file is distributed under GPLv2 because it uses QuickLZ library
# that is distributed under GPLv2.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import binascii
import ctypes
import os
import sys
import tkinter
import tkinter.ttk

def compress(root, combo_level, data):
    level = combo_level.get()

    try:
        qlzlib = ctypes.windll.LoadLibrary("Compression/quicklz150_64_%s_safe.dll" % level)

        scratch_size = 676000
        scratch = ctypes.create_string_buffer(scratch_size)
        compressed = ctypes.create_string_buffer(len(data) * 2)
        final_size = qlzlib.qlz_compress(ctypes.c_char_p(data), compressed, len(data), scratch)

        if final_size == 0:
            raise Exception

        compressed = compressed[:final_size]
        sys.stdout.write(str(binascii.b2a_hex(compressed).decode()))

    except Exception as e:
        print(e, file=sys.stderr)
        exit(1)

    root.quit()

data = binascii.a2b_hex(sys.stdin.read())

dlls = ("quicklz150_64_1_safe.dll", "quicklz150_64_2_safe.dll", "quicklz150_64_3_safe.dll")

for f in dlls:
    if not os.path.exists("Compression/" + f):
        exit(-1) # QuickLZ DLL is not installed

root = tkinter.Tk()
root.title("QuickLZ compress")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_level = tkinter.Label(root, text="Compression level:")
label_level.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_level = tkinter.ttk.Combobox(root, width=18, state="readonly")
combo_level["values"] = ("1", "2", "3")
combo_level.current(0)
combo_level.grid(row=0, column=1, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda root=root, combo_level=combo_level, data=data: compress(root, combo_level, data)))
button.grid(row=4, column=0, padx=5, pady=5, columnspan=2)

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/2.5), (h/2.5)))

root.mainloop()
