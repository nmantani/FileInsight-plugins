#
# Switch file tabs - Switch file tabs with a listbox
#
# Copyright (c) 2022, Nobutaka Mantani
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
import tkinter.messagebox

sys.path.append("./lib")
import dialog_base

class SwichFileTabsDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        # Read list of tabs from stdin
        tabs = sys.stdin.readlines()

        max_len = 0
        for t in tabs:
            if len(t) > max_len:
                max_len = len(t)

        self.strvar_tabs = tkinter.StringVar(value=tabs)
        self.listbox = tkinter.Listbox(self.root, selectmode="browse", listvariable=self.strvar_tabs, width=max_len+10, height=16)
        self.scrollbar = tkinter.ttk.Scrollbar(self.root, orient='vertical', command=self.listbox.yview)
        self.listbox["yscrollcommand"] = self.scrollbar.set
        self.listbox.grid(row=0, column=0, padx=5, pady=5)
        self.scrollbar.grid(row=0, column=1, sticky=(tkinter.N, tkinter.S))
        self.listbox.selection_set(0)
        self.listbox.focus() # Focus to this widget

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=1, column=0, padx=5, pady=5)

        # Set callback functions
        for x in (self.listbox, self.button):
            x.bind("<Return>", lambda event: self.process())

    def process(self, **kwargs):
        print("%d" % self.listbox.curselection())
        self.root.quit()

if __name__ == "__main__":
    dialog = SwichFileTabsDialog(title="Switch file tabs")
    dialog.show()
