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

import base64
import os
import sys
import time
import Tkinter
import tkMessageBox
import subprocess
import winreg

# PLEASE PUT YOUR FAVORITE PROGRAMS HERE!
PROGRAMS = ("IDA Free", "C:\\Program Files\\IDA Freeware 7.0\\ida64.exe",
            "VS Code", "%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe",
            "MS Paint", "C:\\Windows\\system32\\mspaint.exe")

filename = sys.argv[1]

root = Tkinter.Tk()
root.bind("<FocusOut>", lambda x:root.quit())

# Adjust menu position
x = int(sys.argv[2])
if x > 10:
    x = x - 10
y = int(sys.argv[3])
if y > 10:
    y = y - 10

# Add menu items
menu1 = Tkinter.Menu(root, tearoff=False)
menu2 = Tkinter.Menu(menu1, tearoff=False)
menu1.add_cascade(label="Send to", menu=menu2)

# Add special menu items
PROGRAMS += ("CyberChef", "CyberChef")
PROGRAMS += ("Customize menu", "Customize menu")

for i in range(0, len(PROGRAMS), 2):
    def launch(program=PROGRAMS[i+1], filename=filename):
        if program == "CyberChef":
            print os.path.getsize(filename)
            if os.path.getsize(filename) > 24000:
                tkMessageBox.showwarning(None, message="Data size exceeds 24000 bytes. Sent data will be truncated (due to limit of command line argument length).")
            cyberchef_input = open(filename, "rb").read(24000)
            cyberchef_input = base64.b64encode(cyberchef_input)
            cyberchef_input = cyberchef_input.replace("=", "")

            cyberchef_url = "file:///%s%s/Desktop/cyberchef.htm#input=%s" % (os.getenv("HOMEDRIVE"), os.getenv("HOMEPATH").replace("\\", "/"), cyberchef_input)

            # Get path of default browser because "start" built-in command of command prompt drops URL parameters with "file:///" URL scheme
            reg_key = winreg.OpenKeyEx(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice")
            progid, regtype = winreg.QueryValueEx(reg_key, "ProgId")
            winreg.CloseKey(reg_key)
            reg_key = winreg.OpenKeyEx(winreg.HKEY_CLASSES_ROOT, "%s\\shell\\open\\command" % progid)
            browser_cmd, regtype = winreg.QueryValueEx(reg_key, "")
            winreg.CloseKey(reg_key)
            browser_cmd = browser_cmd.replace("%1", cyberchef_url)
            p = subprocess.Popen(browser_cmd)
            p.wait()
        elif program == "Customize menu":
            tkMessageBox.showinfo(None, message="Please edit 'PROGRAMS' variable in send_to.py to customize menu.")
            p = subprocess.Popen(["C:\\Windows\\notepad.exe", __file__])
            p.wait()
        else:
            localappdata = os.environ["LOCALAPPDATA"]
            localappdata = localappdata.replace("\\", "\\\\")
            program = program.replace("%LOCALAPPDATA%", localappdata)
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

time.sleep(5) # Wait five seconds to open the file
os.remove(filename) # Cleanup
