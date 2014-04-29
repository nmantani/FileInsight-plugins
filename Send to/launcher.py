#
# Send to - Send selected region (the whole file if not selected) to other programs
#
# Copyright (c) 2014, Nobutaka Mantani
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

import os
import sys
import time
import Tkinter
import tkMessageBox
import subprocess

# PLEASE PUT YOUR FAVORITE PROGRAMS HERE!
PROGRAMS = ("TrID", "C:\\Program Files (x86)\\trid_net\\TrIDNet.exe",
            "PEInsider", "C:\\Program Files (x86)\\Cerbero\\PEInsider\\peinsider.exe",
            "IDA", "C:\\Program Files (x86)\\IDA Free\\idag.exe",
            "Notepad", "C:\\Windows\\notepad.exe",
            "Paint", "C:\\Windows\\system32\\mspaint.exe")

filename = sys.argv[1]

# Adjust menu position
x = int(sys.argv[2])
if x > 20:
    x = x - 20
y = int(sys.argv[3])
if y > 20:
    y = y - 20

root = Tkinter.Tk()
root.bind("<FocusOut>", lambda x:root.quit())

# Add menu items
menu1 = Tkinter.Menu(root, tearoff=False)
menu2 = Tkinter.Menu(menu1, tearoff=False)
menu1.add_cascade(label="Send to", menu=menu2)

for i in range(0, len(PROGRAMS), 2):
    def launch(program=PROGRAMS[i+1], filename=filename):
        if os.path.exists(program):
            p = subprocess.Popen([program, filename])
            p.wait()
        else:
            msg = "%s does not exist." % program
            tkMessageBox.showerror("Error", msg)
        root.quit()

    menu2.add_command(label=PROGRAMS[i], command=launch)

root.withdraw() # Hide root window
menu1.post(x, y) # Show popup menu

root.mainloop()

os.remove(filename) # Cleanup


