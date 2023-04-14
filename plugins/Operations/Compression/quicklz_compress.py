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

import ctypes
import os
import sys
import tkinter
import tkinter.ttk

sys.path.append("./lib")
import dialog_base

class QuickLZCompressDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])
        self.data = kwargs["data"]

        self.label_level = tkinter.Label(self.root, text="Compression level:")
        self.label_level.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_level = tkinter.ttk.Combobox(self.root, width=4, state="readonly")
        self.combo_level["values"] = ("1", "2", "3")
        self.combo_level.current(0)
        self.combo_level.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=4, column=0, padx=5, pady=5, columnspan=2)
        self.button.focus() # Focus to this widget

        # Set callback functions
        self.combo_level.bind("<Return>", lambda event: self.process())
        self.button.bind("<Return>", lambda event: self.process())

    def process(self, **kwargs):
        level = self.combo_level.get()

        try:
            qlzlib = ctypes.windll.LoadLibrary("Compression/quicklz150_64_%s_safe.dll" % level)

            scratch_size = 676000
            scratch = ctypes.create_string_buffer(scratch_size)
            compressed = ctypes.create_string_buffer(len(self.data) * 2)
            final_size = qlzlib.qlz_compress(ctypes.c_char_p(self.data), compressed, len(self.data), scratch)

            if final_size == 0:
                raise Exception

            compressed = compressed[:final_size]
            sys.stdout.buffer.write(compressed)

        except Exception as e:
            print(e, file=sys.stderr)
            exit(1)

        self.root.quit()

if __name__ == "__main__":
    dlls = ("quicklz150_64_1_safe.dll", "quicklz150_64_2_safe.dll", "quicklz150_64_3_safe.dll")

    for f in dlls:
        if not os.path.exists("Compression/" + f):
            exit(-1) # QuickLZ DLL is not installed

    data = sys.stdin.buffer.read()

    dialog = QuickLZCompressDialog(title="QuickLZ compress", data=data)
    dialog.show()
