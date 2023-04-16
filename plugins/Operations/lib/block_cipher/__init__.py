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

class BlockCipherDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])
        self.data = kwargs["data"]

        if "use_key_length" in kwargs:
            use_key_length = kwargs["use_key_length"]
        else:
            use_key_length = False

        if "show_ctr_label" in kwargs:
            self.show_ctr_label = kwargs["show_ctr_label"]
        else:
            self.show_ctr_label = True

        self.label_mode = tkinter.Label(self.root, text="Mode:")
        self.label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_mode = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_mode["values"] = ("ECB", "CBC", "CFB", "OFB", "CTR")
        self.combo_mode.current(0)
        self.combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # For AES, Camellia and RC6
        if use_key_length:
            self.label_key_length = tkinter.Label(self.root, text="Key length:")
            self.label_key_length.grid(row=0, column=2, padx=5, pady=5, sticky="w")

            self.combo_key_length = tkinter.ttk.Combobox(self.root, width=20, state="readonly")
            self.combo_key_length["values"] = ("128 bits (16 bytes)", "192 bits (24 bytes)", "256 bits (32 bytes)")
            self.combo_key_length.current(0)
            self.combo_key_length.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        self.label_key_type = tkinter.Label(self.root, text="Key type:")
        self.label_key_type.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.combo_key_type = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_key_type["values"] = ("Text", "Hex")
        self.combo_key_type.current(0)
        self.combo_key_type.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.label_key = tkinter.Label(self.root, text="Key:")
        self.label_key.grid(row=1, column=2, padx=5, pady=5, sticky="w")

        self.entry_key = tkinter.Entry(width=32)
        self.entry_key.grid(row=1, column=3, padx=5, pady=5, sticky="w")
        self.entry_key.focus() # Focus to this widget

        self.label_iv_type = tkinter.Label(self.root, text="IV type:")
        self.label_iv_type.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.combo_iv_type = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_iv_type["values"] = ("Text", "Hex")
        self.combo_iv_type.current(0)
        self.combo_iv_type.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        self.label_iv = tkinter.Label(self.root, text="IV:")
        self.label_iv.grid(row=2, column=2, padx=5, pady=5, sticky="w")

        self.entry_iv = tkinter.Entry(width=32)
        self.entry_iv.grid(row=2, column=3, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=3, column=0, padx=5, pady=5, columnspan=4)

        if self.show_ctr_label:
            self.label_ctr = tkinter.Label(self.root, text="Note:\nThe first half of IV is used as the nonce and the second half is used as\nthe initial value of the counter.", justify="left")

            self.label_ctr.grid(row=4, column=0, padx=5, pady=5, columnspan=4, sticky="w")
            self.label_ctr.grid_remove()

        # Set callback functions
        self.combo_mode.bind('<<ComboboxSelected>>', lambda event: self.combo_mode_selected())
        self.combo_mode.bind("<Return>", lambda event: self.process())

        if use_key_length:
            self.combo_key_length.bind("<Return>", lambda event: self.process())

        self.combo_key_type.bind("<Return>", lambda event: self.process())
        self.entry_key.bind("<Return>", lambda event: self.process())
        self.combo_iv_type.bind("<Return>", lambda event: self.process())
        self.entry_iv.bind("<Return>", lambda event: self.process())
        self.button.bind("<Return>", lambda event: self.process())

        # These are disabled in the initial state (ECB mode)
        self.combo_iv_type.configure(state = "disabled")
        self.entry_iv.configure(state = "disabled")

    def combo_mode_selected(self, **kwargs):
        mode = self.combo_mode.get()

        if mode == "ECB":
            self.combo_iv_type.configure(state = "disabled")
            self.entry_iv.configure(state = "disabled")
        else:
            self.combo_iv_type.configure(state = "readonly")
            self.entry_iv.configure(state = "normal")

        if self.show_ctr_label:
            if mode == "CTR":
                self.label_ctr.grid()
            else:
                self.label_ctr.grid_remove()

class TEADialogBase(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])
        self.data = kwargs["data"]

        if "use_single_block" in kwargs:
            self.use_single_block = kwargs["use_single_block"]
        else:
            self.use_single_block = False

        if "show_ctr_label" in kwargs:
            self.show_ctr_label = kwargs["show_ctr_label"]
        else:
            self.show_ctr_label = True

        self.label_mode = tkinter.Label(self.root, text="Mode:")
        self.label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_mode = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_mode["values"] = ("ECB", "CBC", "CFB", "OFB", "CTR")
        self.combo_mode.current(0)
        self.combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.label_key_type = tkinter.Label(self.root, text="Key type:")
        self.label_key_type.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.combo_key_type = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_key_type["values"] = ("Text", "Hex")
        self.combo_key_type.current(0)
        self.combo_key_type.grid(row=1, column=1, padx=5, pady=5)

        self.label_key = tkinter.Label(self.root, text="Key:")
        self.label_key.grid(row=1, column=2, padx=5, pady=5, sticky="w")

        self.entry_key = tkinter.Entry(width=32)
        self.entry_key.grid(row=1, column=3, padx=5, pady=5, sticky="w")
        self.entry_key.focus() # Focus to this widget

        self.label_iv_type = tkinter.Label(self.root, text="IV type:")
        self.label_iv_type.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.combo_iv_type = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_iv_type["values"] = ("Text", "Hex")
        self.combo_iv_type.current(0)
        self.combo_iv_type.grid(row=2, column=1, padx=5, pady=5)

        self.label_iv = tkinter.Label(self.root, text="IV:")
        self.label_iv.grid(row=2, column=2, padx=5, pady=5, sticky="w")

        self.entry_iv = tkinter.Entry(width=32)
        self.entry_iv.grid(row=2, column=3, padx=5, pady=5, sticky="w")

        self.label_endianness = tkinter.Label(self.root, text="Endianness:")
        self.label_endianness.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.combo_endianness = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_endianness["values"] = ("little", "big")
        self.combo_endianness.current(0)
        self.combo_endianness.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        if self.use_single_block:
            self.label_single_block = tkinter.Label(self.root, text="Treat input data as a single block\n(common behaviour of many\nimplementations):", justify="left")
            self.label_single_block.grid(row=4, column=0, padx=5, pady=5, sticky="w", columnspan=3)
            self.bool_single_block = tkinter.BooleanVar()
            self.bool_single_block.set(True)
            self.check_single_block = tkinter.Checkbutton(self.root, variable=self.bool_single_block, text="", onvalue=True, offvalue=False, command=(lambda: self.check_single_block_changed()))
            self.check_single_block.grid(row=4, column=3, padx=5, pady=5, sticky="w")

            self.label_block_size = tkinter.Label(self.root, text="Block size (bytes):")
            self.label_block_size.grid(row=5, column=0, padx=5, pady=5, sticky="w")

            self.block_size = tkinter.StringVar()
            self.block_size.set("8")
            self.block_size.trace("w", lambda *_: self.block_size_changed())
            self.spin_block_size = tkinter.Spinbox(self.root, textvariable=self.block_size, width=6, from_=1, to=255)
            self.spin_block_size.grid(row=5, column=1, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=6, column=0, padx=5, pady=5, columnspan=4)

        if self.show_ctr_label:
            self.label_ctr = tkinter.Label(self.root, text="Note:\nThe first half of IV is used as the nonce and the second half is used as\nthe initial value of the counter.", justify="left")

            self.label_ctr.grid(row=7, column=0, padx=5, pady=5, columnspan=4, sticky="w")
            self.label_ctr.grid_remove()

        # Set callback functions
        self.combo_mode.bind('<<ComboboxSelected>>', lambda event: self.combo_mode_selected())
        self.combo_mode.bind("<Return>", lambda event: self.process())
        self.combo_endianness.bind("<Return>", lambda event: self.process())
        self.combo_key_type.bind("<Return>", lambda event: self.process())
        self.entry_key.bind("<Return>", lambda event: self.process())
        self.combo_iv_type.bind("<Return>", lambda event: self.process())
        self.entry_iv.bind("<Return>", lambda event: self.process())

        if self.use_single_block:
            self.spin_block_size.bind("<Return>", lambda event: self.process())

        self.button.bind("<Return>", lambda event: self.process())

        # These are disabled in the initial state (ECB mode)
        self.combo_iv_type.configure(state = "disabled")
        self.entry_iv.configure(state = "disabled")

        if self.use_single_block:
            # Disabled in the initial state
            self.spin_block_size.configure(state="disabled")

    def combo_mode_selected(self, **kwargs):
        mode = self.combo_mode.get()

        if mode == "ECB":
            self.combo_iv_type.configure(state = "disabled")
            self.entry_iv.configure(state = "disabled")
        else:
            self.combo_iv_type.configure(state = "readonly")
            self.entry_iv.configure(state = "normal")

        if self.show_ctr_label:
            if mode == "CTR":
                self.label_ctr.grid()
            else:
                self.label_ctr.grid_remove()

    def block_size_changed(self, *args):
        s = self.block_size.get()
        if not re.match("^([0-9])+$", s):
            self.block_size.set("8")
        elif int(s) < 8:
            self.block_size.set("8")

    def check_single_block_changed(self, *args):
        if self.bool_single_block.get() == True:
            self.spin_block_size.configure(state="disabled")
        else:
            self.spin_block_size.configure(state="normal")
        return
