#
# Parsing file structure of selected region (the whole file if not selected)
# with Kaitai Struct
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

parser_dict = {}

parser_dict["Archive"] = ("gzip", "rar", "zip")
parser_dict["Executable"] = ("elf", "microsoft_pe")
parser_dict["Filesystem"] = ("mbr_partition_table",)
parser_dict["Image"] = ("bmp", "gif", "jpeg", "png")
parser_dict["Windows-specific"] = ("windows_lnk_file",)

root = tkinter.Tk()
root.bind("<FocusOut>", lambda x:root.quit()) # Exit on focusout

# Adjust menu position
x = int(sys.argv[1])
if x > 10:
    x = x - 10
y = int(sys.argv[2])
if y > 10:
    y = y - 10

# Add menu items
categories = ("Archive", "Executable", "Filesystem", "Image", "Windows-specific")
menu = tkinter.Menu(root, tearoff=False)
menu_dict = {}

for c in categories:
    menu_dict[c] = tkinter.Menu(menu, tearoff=False)
    menu.add_cascade(label=c, menu=menu_dict[c])

    for i in range(0, len(parser_dict[c])):
        def menuclick_callback(label=parser_dict[c][i]):
            print(label, end="")
            root.quit()

        menu_dict[c].add_command(label=parser_dict[c][i], command=menuclick_callback)

root.withdraw() # Hide root window
menu.post(x, y) # Show popup menu

root.mainloop()
