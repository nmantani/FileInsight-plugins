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

import collections
import json
import os
import sys
import tkinter
import tkinter.colorchooser

config_file_name = "colorchooser.json"

# Load config file
if os.path.exists(config_file_name):
    try:
        f = open(config_file_name, "r")
        config = json.load(f, object_pairs_hook=collections.OrderedDict)
        f.close()
    except:
        tkinter.messagebox.showerror("Error:", message="Failed to load %s ." % os.path.abspath(config_file_name))
else:
    # Set default color
    config = collections.OrderedDict()
    config["color"] = (255, 128, 128)

    # Create new config file
    f = open(config_file_name, "w")
    json.dump(config, f, indent=4)
    f.close()

root = tkinter.Tk()

root.attributes("-topmost", True) # Set root window to topmost to make color chooser dialog modal
root.withdraw() # Hide root window

color = tkinter.colorchooser.askcolor(color=tuple(config["color"]))

if color[1] == None:
    sys.exit(1)
else:
    print(color[1])

    red = int(color[1][1:3], 16)
    green = int(color[1][3:5], 16)
    blue = int(color[1][5:7], 16)
    config["color"] = (red, green, blue)

    # Update config file
    f = open(config_file_name, "w")
    json.dump(config, f, indent=4)
    f.close()

    sys.exit(0)
