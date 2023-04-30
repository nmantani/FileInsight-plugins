#
# Visual encrypt - Encode selected region with visual encrypt algorithm
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

import re
import sys
import tkinter
import tkinter.messagebox

sys.path.append("./lib")
import dialog_base

class VisualEncryptDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label = tkinter.Label(self.root, text="XOR key length:")
        self.label.grid(row=0, column=0, padx=5, pady=5)
        self.key_length = tkinter.StringVar()
        self.key_length.set("1")
        self.key_length.trace("w", lambda *_: self.key_length_changed())
        self.spin = tkinter.Spinbox(self.root, textvariable=self.key_length, width=4, from_=1, to=100)
        self.spin.grid(row=0, column=1, padx=5, pady=5)
        self.button = tkinter.Button(self.root, text='OK', command=(lambda: self.print_key_length()))
        self.button.grid(row=0, column=2, padx=5, pady=5)
        self.button.focus() # Focus to this widget

        # Set callback functions
        self.spin.bind("<Return>", lambda event: self.print_key_length())
        self.button.bind("<Return>", lambda event: self.print_key_length())

    # Print key length to stdout
    def print_key_length(self):
        if self.spin.get() == "":
            tkinter.messagebox.showerror("Error:", message="XOR key length is empty.")
            return
        else:
            print(self.spin.get())
            self.root.quit()

    def key_length_changed(self):
        if not re.match("^-?([0-9])+$", self.key_length.get()):
            s = re.sub("[^-0-9]", "", self.key_length.get())
            if re.match("[0-9]+-", s):
                s = s.replace("-", "")
                self.key_length.set(s)
            else:
                self.key_length.set(s)
        elif int(self.key_length.get()) < 1:
            self.key_length.set("1")

if __name__ == "__main__":
    dialog = VisualEncryptDialog(title="Visual encrypt / decrypt")
    dialog.show()
