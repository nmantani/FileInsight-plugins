#
# Strings - Extract text strings from selected region (the whole file if not selected)
#
# Copyright (c) 2019, Nobutaka Mantani
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

sys.path.append("./lib")
import dialog_base

class StringsDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label_mode = tkinter.Label(self.root, text="Mode:")
        self.label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_mode = tkinter.ttk.Combobox(self.root, width=18, state="readonly")
        self.combo_mode["values"] = ("ASCII + UTF-16", "ASCII", "UTF-16")
        self.combo_mode.current(0)
        self.combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.label_length = tkinter.Label(self.root, text='Minimum length:')
        self.label_length.grid(row=1, column=0, padx=5, pady=5)
        self.amount = tkinter.StringVar()
        self.amount.set("4")
        self.amount.trace("w", self.amount_changed)

        self.spin = tkinter.Spinbox(self.root, textvariable=self.amount, width=4, from_=1, to=100)
        self.spin.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.label_postprocess = tkinter.Label(self.root, text="Post-process:")
        self.label_postprocess.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.combo_postprocess = tkinter.ttk.Combobox(self.root, width=18, state="readonly")
        self.combo_postprocess["values"] = ("None", "Show offset", "Remove duplicates")
        self.combo_postprocess.current(0)
        self.combo_postprocess.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        self.bool_decode = tkinter.BooleanVar()
        self.bool_decode.set(False)
        self.check_decode = tkinter.Checkbutton(self.root, variable=self.bool_decode, text='Decode hex / BASE64 encoded text strings', onvalue=True, offvalue=False)
        self.check_decode.grid(row=3, column=0, padx=5, pady=5, columnspan=2)

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.print_param()))
        self.button.grid(row=4, column=0, padx=5, pady=5, columnspan=2)
        self.button.focus() # Focus to this widget

        # Set callback functions
        for x in (self.combo_mode, self.spin, self.combo_postprocess, self.check_decode, self.button):
            x.bind("<Return>", lambda event: self.print_param())

    # Print parameters
    def print_param(self):
        mode = self.combo_mode.get()
        s = self.spin.get()
        if s == "":
            min_len = 1
        else:
            min_len = int(s)
        postprocess = self.combo_postprocess.get()
        decode = self.bool_decode.get()

        print("%s\t%s\t%s\t%s" % (mode, min_len, postprocess, decode))

        self.root.quit()

    def amount_changed(self, *args):
        if not re.match("^-?([0-9])+$", self.amount.get()):
            s = re.sub("[^-0-9]", "", self.amount.get())
            if re.match("[0-9]+-", s):
                s = s.replace("-", "")
                self.amount.set(s)
            else:
                self.amount.set(s)
        elif int(self.amount.get()) < 1:
            self.amount.set("1")

if __name__ == "__main__":
    dialog = StringsDialog(title="Strings")
    dialog.show()
