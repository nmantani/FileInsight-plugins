#
# Unit setting dialog for "Change endianness" plugin
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

class ChangeEndiannessDialog(dialog_base.DialogBase):
    def add_widgets(self, **kwargs):
        self.label_unit = tkinter.Label(self.root, text="Unit to change:")
        self.label_unit.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.combo_unit = tkinter.ttk.Combobox(self.root, width=18, state="readonly")
        self.combo_unit["values"] = ("WORD (2 bytes)", "DWORD (4 bytes)", "QWORD (8 bytes)")
        self.combo_unit.current(0)
        self.combo_unit.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.combo_unit.focus() # Focus to this widget

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=1, column=0, padx=5, pady=5, columnspan=2)

        # Set callback functions
        self.button.bind("<Return>", lambda event: self.process())
        self.combo_unit.bind("<Return>", lambda event: self.process())

    def process(self, **kwargs):
        print("%s" % self.combo_unit.get())
        self.root.quit()

if __name__ == "__main__":
    dialog = ChangeEndiannessDialog("Change endianness")
    dialog.add_widgets()
    dialog.show()
