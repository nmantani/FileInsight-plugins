#
# Copyright (c) 2023, Nobutaka Mantani
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
import tkinter.ttk
import tkinter.messagebox

sys.path.append("./lib")
import dialog_base

class DecrementalXORDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label_key = tkinter.Label(self.root, text="XOR key (single byte in hex like 4e):")
        self.label_key.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.key = tkinter.StringVar()
        self.key.trace("w", lambda *_: self.entry_key_changed())
        self.entry_key = tkinter.Entry(textvariable=self.key, width=4)
        self.entry_key.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.entry_key.focus() # Focus to this widget

        self.label_step = tkinter.Label(self.root, text="Decrement step (decimal):")
        self.label_step.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.step = tkinter.StringVar()
        self.step.set("1")
        self.step.trace("w", lambda *_: self.step_changed())
        self.spin_step = tkinter.Spinbox(self.root, textvariable=self.step, width=5, from_=1, to=255)
        self.spin_step.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=2, column=0, padx=5, pady=5, columnspan=2)

        # Set callback functions
        self.entry_key.bind("<Return>", lambda event: self.process())
        self.spin_step.bind("<Return>", lambda event: self.process())
        self.button.bind("<Return>", lambda event: self.process())

    def process(self):
        key = self.entry_key.get()
        step = self.spin_step.get()

        if key == "":
            tkinter.messagebox.showerror("Error:", message="XOR key is empty.")
            return
        elif step == "":
            tkinter.messagebox.showerror("Error:", message="Step is empty.")
            return
        elif not re.match("^([0-9A-Fa-f]{2})$", key):
            tkinter.messagebox.showerror("Error:", message="XOR key must be a single byte.")
            return
        elif int(step) < 1 or int(step) > 255:
            tkinter.messagebox.showerror("Error:", message="Step must be between 1 and 255.")
            return

        print(f"{key}\t{int(step)}")
        self.root.quit()

    def entry_key_changed(self):
        self.key.set(re.sub("[^0-9A-Fa-f]", "", self.key.get()))

    def step_changed(self):
        s = self.step.get()
        if s == "":
            return
        elif not re.match("^([0-9])+$", s):
            self.step.set("1")
        elif int(s) < 1:
            self.step.set("1")
        elif int(s) > 255:
            self.step.set("255")

if __name__ == "__main__":
    dialog = DecrementalXORDialog(title="Decremental XOR")
    dialog.show()
