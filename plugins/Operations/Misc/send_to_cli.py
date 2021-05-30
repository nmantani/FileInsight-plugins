#
# Send to (CLI) - Send selected region (the whole file if not selected) to other CLI program and get output
#
# Copyright (c) 2021, Nobutaka Mantani
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
root.bind("<FocusOut>", lambda x:root.quit())
root.withdraw() # Hide root window

config_file_name = "Misc/send_to_cli.json"

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
    programs["capa"] = "%HOMEPATH%\\Desktop\\tools\\capa\\capa.exe"
    programs["floss"] = "%HOMEPATH%\\Desktop\\tools\\floss\\floss.exe"
    programs["pelook"] = ["%HOMEPATH%\\Desktop\\tools\\pelook\\pelook.exe", "-x"]
    programs["olevba"] = ["%LOCALAPPDATA%\\Programs\\Python\\Python39\\Scripts\\olevba.exe", "--decode"]
    programs["rtfobj"] = "%LOCALAPPDATA%\\Programs\\Python\\Python39\\Scripts\\rtfobj.exe"

    # Create new config file
    f = open(config_file_name, "w")
    json.dump(programs, f, indent=4)
    f.close()

# Add special menu items
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
menu1.add_cascade(label="Send to (CLI)", menu=menu2)

for key,val in programs.items():
    def launch(name=key, program=val, filename=filename):
        if name == "Customize menu":
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
                editor_cmd = editor_cmd.replace("%1", "Misc\\send_to_cli.json")
                tkinter.messagebox.showinfo(None, message="Please edit 'send_to_cli.json' to customize menu.")
                p = subprocess.Popen(editor_cmd)
                p.wait()
            except Exception as e:
                # Fallback to Notepad
                tkinter.messagebox.showinfo(None, message="Please edit 'send_to_cli.json' to customize menu.")
                p = subprocess.Popen(["C:\\Windows\\notepad.exe", "Misc\\send_to_cli.json"])
                p.wait()
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

                sys.stdout.buffer.write(b"Command line:\n")
                sys.stdout.buffer.write((" ".join(args)).encode("UTF-8") + b"\n\n")

                p = subprocess.Popen(args=args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout_data, stderr_data = p.communicate()
                ret = p.wait()
                sys.stdout.buffer.write(stdout_data)
                sys.stderr.buffer.write(stderr_data)
            else:
                tkinter.messagebox.showerror("Error:", message="%s is not found. Please select the file." % program_path)
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

                    sys.stdout.buffer.write(b"Command line:")
                    sys.stdout.buffer.write((" ".join(args)).encode("UTF-8") + b"\n\n")

                    p = subprocess.Popen(args=args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout_data, stderr_data = p.communicate()
                    ret = p.wait()
                    sys.stdout.buffer.write(stdout_data)
                    sys.stderr.buffer.write(stderr_data)
        root.quit()

    menu2.add_command(label=key, command=launch)

menu1.post(x, y) # Show popup menu
root.mainloop()

os.remove(filename) # Cleanup
