#
# Identify type of strings such as API keys and cryptocurrency wallet addresses
# in the selected region (the whole file if not selected) with lemmeknow
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

import sys
import tkinter
import tkinter.ttk

sys.path.append("./lib")
import dialog_base

class StringTypeDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label_mode = tkinter.Label(self.root, text="Enable boundaryless mode\n(for more string type identification\nbut more false positives):", justify="left")
        self.label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.bool_mode = tkinter.BooleanVar()
        self.bool_mode.set(False)
        self.check_mode = tkinter.Checkbutton(self.root, variable=self.bool_mode, text="", onvalue=True, offvalue=False, command=(lambda: None))
        self.check_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text='OK', command=(lambda: self.print_setting()))
        self.button.grid(row=1, column=0, padx=5, pady=5, columnspan=2)
        self.button.focus() # Focus to this widget

        # Set callback functions
        for x in (self.check_mode, self.button):
            x.bind("<Return>", lambda event: self.print_setting())

    # Print setting to stdout
    def print_setting(self):
        print(self.bool_mode.get())
        self.root.quit()

if __name__ == "__main__":
    dialog = StringTypeDialog(title="String type")
    dialog.show()
