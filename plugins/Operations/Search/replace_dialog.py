#
# Replace - Replace matched data in selected region (the whole file if not selected)
# with specified data
#
# Copyright (c) 2018, Nobutaka Mantani
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

class ReplaceDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label1 = tkinter.Label(self.root, text="Search keyword\n(Python regular expression):", justify="left")
        self.label1.grid(row=0, column=0, padx=5, pady=5, columnspan=2, sticky="w")

        self.entry1 = tkinter.Entry(self.root, width=40)
        self.entry1.grid(row=0, column=2, padx=5, pady=5)
        self.entry1.focus() # Focus to this widget

        self.label2 = tkinter.Label(self.root, text="Replacement:")
        self.label2.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.combo = tkinter.ttk.Combobox(self.root, state="readonly", width=4)
        self.combo["values"] = ["Text", "Hex"]
        self.combo.current(0)
        self.combo.grid(row=1, column=1, padx=5, pady=5)

        self.entry2 = tkinter.Entry(self.root, width=40)
        self.entry2.grid(row=1, column=2, padx=5, pady=5)

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.get_input()))
        self.button.grid(row=2, column=0, padx=5, pady=5, columnspan=3)

        # Set callback functions
        for x in (self.entry1, self.combo, self.entry2, self.button):
            x.bind("<Return>", lambda event: self.get_input())

    # Print selected items
    def get_input(self):
        print(self.entry1.get())
        print(self.entry2.get())
        print(self.combo.get())
        self.root.quit()

if __name__ == "__main__":
    dialog = ReplaceDialog(title="Replace")
    dialog.show()
