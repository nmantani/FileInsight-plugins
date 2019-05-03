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
import binascii
import collections
import json
import os
import re
import sys
import time
import Tkinter
import tkFileDialog
import tkMessageBox
import subprocess
import winreg

def replace_env_in_path(s):
    env_list = ("SYSTEMROOT", "PROGRAMFILES", "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH")
    for e in env_list:
        p = os.environ[e]
        p = p.replace("\\", "\\\\")
        pattern = "%" + e + "%"
        s = re.sub(pattern, p, s, flags=re.IGNORECASE)

    return s

root = Tkinter.Tk()
root.bind("<FocusOut>", lambda x:root.quit())
root.withdraw() # Hide root window

config_file_name = "send_to.json"

# Load config file
if os.path.exists(config_file_name):
    try:
        f = open(config_file_name, "r")
        programs = json.load(f, object_pairs_hook=collections.OrderedDict)
        f.close()
    except:
        tkMessageBox.showerror("Error:", message="Failed to load %s ." % os.path.abspath(config_file_name))
else:
    # Default external programs
    programs = collections.OrderedDict()
    programs["IDA Free"] = "C:\\Program Files\\IDA Freeware 7.0\\ida64.exe"
    programs["VS Code"] = "%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe"
    programs["MS Paint"] = "C:\\Windows\\system32\\mspaint.exe"
    programs["CyberChef"] = "C:%HOMEPATH%\\Desktop\\cyberchef.htm"

    # Create new config file
    f = open(config_file_name, "w")
    json.dump(programs, f, indent=4)
    f.close()

# Add special menu items
if not "CyberChef" in programs:
    programs["CyberChef"] = "C:%HOMEPATH%\\Desktop\\cyberchef.htm"
if not "Customize menu" in programs:
    programs["Customize menu"] = "Customize menu"

filename = sys.argv[1]

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

for key,val in programs.iteritems():
    def launch(name=key, program=val, filename=filename):
        if name == "CyberChef":
            global config_file_name, programs

            if os.path.getsize(filename) > 12000:
                tkMessageBox.showwarning(None, message="Data size exceeds 12000 bytes. Sent data will be truncated (due to limit of command line argument length).")
            cyberchef_input = open(filename, "rb").read(12000)
            # CyberChef input box automatically replace 0x0d with 0x0a and this breaks data integrity.
            # So data have to be converted into hex text before sending to CyberChef.
            # For the detail of the issue, please see https://github.com/gchq/CyberChef/issues/430 .
            # Data size limit is reduced from 24000 bytes to 12000 bytes due to this conversion.
            cyberchef_input = binascii.hexlify(cyberchef_input)
            cyberchef_input = base64.b64encode(cyberchef_input)
            cyberchef_input = cyberchef_input.replace("+", "%2B")
            cyberchef_input = cyberchef_input.replace("=", "")

            program = replace_env_in_path(program)
            if not os.path.exists(program):
                tkMessageBox.showerror("Error:", message="%s is not found. Please select CyberChef HTML file." % program)
                fTyp = [("HTML file","*.htm;*.html")]
                iDir = os.path.abspath(os.getenv("HOMEPATH") + "\\Desktop")
                program = tkFileDialog.askopenfilename(filetypes = fTyp,initialdir = iDir)
            if program == "":
                return
            else:
                programs["CyberChef"] = program

                # Update config file
                f = open(config_file_name, "w")
                json.dump(programs, f, indent=4)
                f.close()

            cyberchef_url = "file:///%s#recipe=From_Hex('Auto')&input=%s" % (program.replace("\\", "/"), cyberchef_input)

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
        elif name == "Customize menu":
            # Get path of default text editor
            try:
                reg_key = winreg.OpenKeyEx(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.txt\\UserChoice")
                progid, regtype = winreg.QueryValueEx(reg_key, "ProgId")
                progid = progid.replace("\\", "\\\\")
                winreg.CloseKey(reg_key)
                reg_key = winreg.OpenKeyEx(winreg.HKEY_CLASSES_ROOT, "%s\\shell\\open\\command" % progid)
                editor_cmd, regtype = winreg.QueryValueEx(reg_key, "")
                winreg.CloseKey(reg_key)
                editor_cmd = replace_env_in_path(editor_cmd)
                editor_cmd = editor_cmd.replace("%1", "send_to.json")
                tkMessageBox.showinfo(None, message="Please edit 'send_to.json' to customize menu.")
                p = subprocess.Popen(editor_cmd)
                p.wait()
            except Exception as e:
                # Fallback to Notepad
                tkMessageBox.showinfo(None, message="Please edit 'send_to.json' to customize menu.")
                p = subprocess.Popen(["C:\\Windows\\notepad.exe", "send_to.json"])
                p.wait()
        else:
            program = replace_env_in_path(program)
            if os.path.exists(program):
                p = subprocess.Popen([program, filename])
                p.wait()
            else:
                msg = "%s does not exist." % program
                tkMessageBox.showerror("Error", msg)
        root.quit()

    menu2.add_command(label=key, command=launch)

menu1.post(x, y) # Show popup menu

root.mainloop()

time.sleep(5) # Wait five seconds to open the file
os.remove(filename) # Cleanup
