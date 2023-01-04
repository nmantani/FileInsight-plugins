#
# Send to (GUI) - Send selected region (the whole file if not selected) to other program
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
import tkinter
import tkinter.filedialog
import tkinter.messagebox
import subprocess
import winreg

def replace_env_in_path(s):
    env_list = ("SYSTEMROOT", "PROGRAMFILES", "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH")
    for e in env_list:
        p = os.environ[e]
        p = p.replace("\\", "\\\\")
        pattern = "%" + e + "%"

        if type(s) == list:
            for i in range(0, len(s)):
                s[i] = re.sub(pattern, p, s[i], flags=re.IGNORECASE)
        else:
            s = re.sub(pattern, p, s, flags=re.IGNORECASE)

    return s

def wait_process_by_name(name):
    """
    Wait until all processes of specified name finish.
    This function is necessary for programs such as VSCode that a created process
    exits immediately and the temporary file is opened by an other process.
    """
    running = True
    while running:
        stdout_data = subprocess.check_output(["tasklist", "/NH"])
        stdout_data = stdout_data.decode()

        running = False
        for line in stdout_data.splitlines():
            if line != "":
                procinfo = line.split()
                if name == procinfo[0]:
                    running = True
        time.sleep(5)

root = tkinter.Tk()
root.bind("<FocusOut>", lambda x:sys.exit(1))
root.attributes("-topmost", True) # Set root window to topmost to make messagebox modal
root.withdraw() # Hide root window

config_file_name = "Misc/send_to.json"

# Load config file
if os.path.exists(config_file_name):
    try:
        f = open(config_file_name, "r")
        programs = json.load(f, object_pairs_hook=collections.OrderedDict)
        f.close()
    except:
        tkinter.messagebox.showerror("Error:", message="Failed to load %s ." % os.path.abspath(config_file_name))
else:
    # Default external programs
    programs = collections.OrderedDict()
    programs["Detect It Easy"] = ["C:%HOMEPATH%\\Documents\\McAfee FileInsight\\plugins\\Operations\\Parsing\\die_win64_portable\\die.exe"]
    programs["IDA Free"] = "C:\\Program Files\\IDA Freeware 8.2\\ida64.exe"
    programs["Cutter"] = ["C:%HOMEPATH%\\Desktop\\tools\\cutter\\cutter.exe", "-A", "1"]
    programs["VS Code"] = "%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe"
    programs["MS Paint"] = "C:\\Windows\\system32\\mspaint.exe"
    programs["CyberChef"] = "C:%HOMEPATH%\\Desktop\\CyberChef_v9.55.0\\CyberChef_v9.55.0.html"

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
menu1 = tkinter.Menu(root, tearoff=False)
menu2 = tkinter.Menu(menu1, tearoff=False)
menu1.add_cascade(label="Send to (GUI)", menu=menu2)

for key,val in programs.items():
    def launch(name=key, program=val, filename=filename):
        if name == "CyberChef":
            global config_file_name, programs

            try:
                if os.path.getsize(filename) > 12000:
                    tkinter.messagebox.showwarning(None, message="Data size exceeds 12000 bytes. Sent data will be truncated (due to limit of command line argument length).")
                cyberchef_input = open(filename, "rb").read(12000)
                # CyberChef input box automatically replace 0x0d with 0x0a and this breaks data integrity.
                # So data have to be converted into hex text before sending to CyberChef.
                # For the detail of the issue, please see https://github.com/gchq/CyberChef/issues/430 .
                # Data size limit is reduced from 24000 bytes to 12000 bytes due to this conversion.
                cyberchef_input = binascii.hexlify(cyberchef_input)
                cyberchef_input = base64.b64encode(cyberchef_input).decode()
                cyberchef_input = cyberchef_input.replace("+", "%2B")
                cyberchef_input = cyberchef_input.replace("=", "")
            except Exception as e:
                tkinter.messagebox.showerror("Error:", message=e)

            program = replace_env_in_path(program)
            if not os.path.exists(program):
                tkinter.messagebox.showerror("Error:", message="%s is not found. Please select CyberChef HTML file." % program)
                fTyp = [("HTML file","*.htm;*.html")]
                iDir = os.path.abspath(os.getenv("HOMEPATH") + "\\Desktop")
                program = tkinter.filedialog.askopenfilename(filetypes = fTyp,initialdir = iDir)
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
            m = re.search('\"(.+?)\"', browser_cmd)
            program = m.group(1)
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
                editor_cmd = editor_cmd.replace("%1", "Misc\\send_to.json")
                tkinter.messagebox.showinfo(None, message="Please edit 'send_to.json' to customize menu.")
                p = subprocess.Popen(editor_cmd)
                p.wait()
            except Exception as e:
                # Fallback to Notepad
                tkinter.messagebox.showinfo(None, message="Please edit 'send_to.json' to customize menu.")
                p = subprocess.Popen(["C:\\Windows\\notepad.exe", "Misc\\send_to.json"])
                p.wait()
            sys.exit(1)
        else:
            program = replace_env_in_path(program)

            if type(program) == list:
                program_path = program[0]
            else:
                program_path = program

            if os.path.exists(program_path):
                if type(program) == list:
                    args = program
                    args.append(filename)
                else:
                    args = [program, filename]

                p = subprocess.Popen(args=args)
                p.wait()
            else:
                tkinter.messagebox.showerror("Error:", message="%s is not found. Please select the file." % program)
                fTyp = [("Executable file","*.exe")]
                iDir = os.path.abspath(os.getenv("PROGRAMFILES"))
                program_path = tkinter.filedialog.askopenfilename(filetypes = fTyp,initialdir = iDir)

                if program_path == "":
                    return
                else:
                    if type(program) == list:
                        program[0] = program_path
                        programs[name] = program
                    else:
                        program = program_path
                        programs[name] = program_path

                    # Update config file
                    f = open(config_file_name, "w")
                    json.dump(programs, f, indent=4)
                    f.close()

                    if type(program) == list:
                        args = program
                        args.append(filename)
                    else:
                        args = [program, filename]

                    p = subprocess.Popen(args=args)
                    p.wait()

        wait_process_by_name(os.path.basename(program_path))
        root.quit()

    menu2.add_command(label=key, command=launch)

menu1.post(x, y) # Show popup menu
root.mainloop()

os.remove(filename) # Cleanup
