#
# QuickLZ decompress - Decompress selected region with QuickLZ compression library
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

import ctypes
import os
import sys
import tkinter
import tkinter.ttk

def decompress(root, combo_level, data):
    level = combo_level.get()

    try:
        qlzlib = ctypes.windll.LoadLibrary("Compression/quicklz150_64_%s_safe.dll" % level)

        scratch_size = 676000
        scratch = ctypes.create_string_buffer(scratch_size)
        decompressed = ctypes.create_string_buffer(len(data) * 2)

        final_size = qlzlib.qlz_decompress(ctypes.c_char_p(data), decompressed, scratch)

        if final_size == 0:
            raise Exception

        decompressed = decompressed[:final_size]
        sys.stdout.buffer.write(decompressed)

    except Exception as e:
        print("Error: compressed data is invalid or compression level does not match.", file=sys.stderr)
        exit(1)

    root.quit()

data = sys.stdin.buffer.read()

dlls = ("quicklz150_64_1_safe.dll", "quicklz150_64_2_safe.dll", "quicklz150_64_3_safe.dll")

for f in dlls:
    if not os.path.exists("Compression/" + f):
        exit(-1) # QuickLZ DLL is not installed

root = tkinter.Tk()
root.title("QuickLZ decompress")
root.protocol("WM_DELETE_WINDOW", (lambda r=root: r.quit()))

label_level = tkinter.Label(root, text="Compression level:")
label_level.grid(row=0, column=0, padx=5, pady=5, sticky="w")

combo_level = tkinter.ttk.Combobox(root, width=18, state="readonly")
combo_level["values"] = ("1", "2", "3")
combo_level.current(0)
combo_level.grid(row=0, column=1, padx=5, pady=5, sticky="w")

button = tkinter.Button(root, text="OK", command=(lambda root=root, combo_level=combo_level, data=data: decompress(root, combo_level, data)))
button.grid(row=4, column=0, padx=5, pady=5, columnspan=2)

# Adjust window position
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.update_idletasks() # Necessary to get width and height of the window
ww = root.winfo_width()
wh = root.winfo_height()
root.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

root.mainloop()
