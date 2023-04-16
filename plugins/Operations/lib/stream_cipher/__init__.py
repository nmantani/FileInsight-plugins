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
import tkinter.messagebox

sys.path.append("./lib")
import dialog_base

class StreamCipherDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])
        self.data = kwargs["data"]

        if "use_nonce" in kwargs:
            self.use_nonce = kwargs["use_nonce"]
        else:
            self.use_nonce = True

        self.label_key_type = tkinter.Label(self.root, text="Key type:")
        self.label_key_type.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_key_type = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_key_type["values"] = ("Text", "Hex")
        self.combo_key_type.current(0)
        self.combo_key_type.grid(row=0, column=1, padx=5, pady=5)

        self.label_key = tkinter.Label(self.root, text="Key:")
        self.label_key.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        self.entry_key = tkinter.Entry(width=48)
        self.entry_key.grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.entry_key.focus() # Focus to this widget

        if self.use_nonce:
            self.label_nonce_type = tkinter.Label(self.root, text="Nonce type:")
            self.label_nonce_type.grid(row=1, column=0, padx=5, pady=5, sticky="w")

            self.combo_nonce_type = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
            self.combo_nonce_type["values"] = ("Text", "Hex")
            self.combo_nonce_type.current(0)
            self.combo_nonce_type.grid(row=1, column=1, padx=5, pady=5)

            self.label_nonce = tkinter.Label(self.root, text="Nonce:")
            self.label_nonce.grid(row=1, column=2, padx=5, pady=5, sticky="w")

            self.entry_nonce = tkinter.Entry(width=48)
            self.entry_nonce.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=2, column=0, padx=5, pady=5, columnspan=4)

        # Set callback functions
        self.combo_key_type.bind("<Return>", lambda event: self.process())
        self.entry_key.bind("<Return>", lambda event: self.process())

        if self.use_nonce:
            self.combo_nonce_type.bind("<Return>", lambda event: self.process())
            self.entry_nonce.bind("<Return>", lambda event: self.process())

        self.button.bind("<Return>", lambda event: self.process())
