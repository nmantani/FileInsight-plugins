#
# Extract VBA macro - Extract Microsoft Office VBA macro from selected region
# (the whole file if not selected)
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

class ExtractVBAMacroDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label_method = tkinter.Label(self.root, text="Extraction method:")
        self.label_method.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_method = tkinter.ttk.Combobox(self.root, width=20, state="readonly")
        self.combo_method["values"] = ("Extract source code",
                                       "Decompile p-code")
        self.combo_method.current(0)
        self.combo_method.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.label_retry = tkinter.Label(self.root, text="Try also another extraction\nmethod if VBA stomping is\ndetected:", justify="left")
        self.label_retry.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.bool_retry = tkinter.BooleanVar()
        self.bool_retry.set(True)
        self.check_retry = tkinter.Checkbutton(self.root, variable=self.bool_retry, text="", onvalue=True, offvalue=False, command=(lambda: None))
        self.check_retry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text='OK', command=(lambda: self.print_setting()))
        self.button.grid(row=2, column=0, padx=5, pady=5, columnspan=3)
        self.button.focus() # Focus to this widget

        # Set callback functions
        for x in (self.combo_method, self.check_retry, self.button):
            x.bind("<Return>", lambda event: self.print_setting())

    # Print setting to stdout
    def print_setting(self):
        print("%s\t%s" % (self.combo_method.get(), self.bool_retry.get()))
        self.root.quit()

if __name__ == "__main__":
    dialog = ExtractVBAMacroDialog(title="Extract VBA macro")
    dialog.show()
