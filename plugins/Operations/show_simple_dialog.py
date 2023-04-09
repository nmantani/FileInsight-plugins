#
# Copyright (c) 2020, Nobutaka Mantani
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

sys.path.append("./lib")
import dialog_base

class SimpleDialog(dialog_base.DialogBase):
    def add_widgets(self, **kwargs):
        label_text=kwargs["label_text"]
        self.label = tkinter.Label(self.root, text=label_text)
        self.label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.entry = tkinter.Entry(self.root, width=80)
        self.entry.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.entry.focus() # Focus to this widget

        self.button = tkinter.Button(self.root, text='OK', command=(lambda: self.process()))
        self.button.grid(row=2, column=0, padx=5, pady=5, sticky="e")

        # Event handlers for hitting enter key
        self.button.bind("<Return>", lambda event: self.process())
        self.entry.bind("<Return>", lambda event: self.process())

    # Print input to stdout
    def process(self, **kwargs):
        print(self.entry.get())
        self.root.quit()

if __name__ == "__main__":
    dialog = SimpleDialog("Dialog")

    if len(sys.argv) < 2:
        label_text = ""
    else:
        label_text = sys.argv[1]

    dialog.add_widgets(label_text=label_text)
    dialog.show()
