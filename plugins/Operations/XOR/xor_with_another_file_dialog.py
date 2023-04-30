#
# XOR with another file - XOR selected region (the whole file if not selected) while using the content of another file as XOR key
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

import sys
import tkinter
import tkinter.ttk

sys.path.append("./lib")
import dialog_base

class XORWithAnotherFileDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])
        files = kwargs["files"]

        max_len = 0
        for f in files:
            if len(f) > max_len:
                max_len = len(f)

        self.label1 = tkinter.Label(self.root, text="File to be XORed:")
        self.label1.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo1 = tkinter.ttk.Combobox(self.root, state="readonly", width=max_len)
        self.combo1["values"] = files
        self.combo1.current(0)
        self.combo1.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.label2 = tkinter.Label(self.root, text="XOR key file:")
        self.label2.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.combo2 = tkinter.ttk.Combobox(self.root, state="readonly", width=max_len)
        self.combo2["values"] = files
        self.combo2.current(1)
        self.combo2.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.label3 = tkinter.Label(self.root, text="XOR key file has to contain only XOR key data.")
        self.label3.grid(row=2, column=0, padx=5, pady=5, sticky="w", columnspan=3)

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.get_selection()))
        self.button.grid(row=3, column=0, padx=5, pady=5, columnspan=3)
        self.button.focus() # Focus to this widget

        # Set callback functions
        for x in (self.combo1, self.combo2, self.button):
            x.bind("<Return>", lambda event: self.get_selection())

    # Print selected items
    def get_selection(self):
        print("%d %d" % (self.combo1.current(), self.combo2.current()))
        self.root.quit()

if __name__ == "__main__":
    # Read list of files from stdin
    files = sys.stdin.readlines()

    dialog = XORWithAnotherFileDialog(title="XOR with another file", files=files)
    dialog.show()
