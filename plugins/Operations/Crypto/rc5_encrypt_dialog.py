#
# RC5 encrypt - Encrypt selected region with RC5
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

import binascii
import re
import sys
import tkinter
import tkinter.ttk
import tkinter.messagebox

sys.path.append("./lib")
import dialog_base

try:
    import refinery.units.crypto.cipher.rc5
except ImportError:
    exit(-2) # Binary Refinery is not installed

class RC5EncryptDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])
        self.data = kwargs["data"]

        self.label_mode = tkinter.Label(self.root, text="Mode:")
        self.label_mode.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_mode = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_mode["values"] = ("ECB", "CBC", "CFB", "OFB", "CTR")
        self.combo_mode.current(0)
        self.combo_mode.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.label_block_size = tkinter.Label(self.root, text="Block size:")
        self.label_block_size.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        self.combo_block_size = tkinter.ttk.Combobox(self.root, width=20, state="readonly")
        self.combo_block_size["values"] = ("32 bits (4 bytes)", "64 bits (8 bytes)", "128 bits (16 bytes)")
        self.combo_block_size.current(1)
        self.combo_block_size.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        self.label_rounds = tkinter.Label(self.root, text="Rounds:")
        self.label_rounds.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.rounds = tkinter.StringVar()
        self.rounds.set("12")
        self.rounds.trace("w", self.rounds_changed)
        self.spin_rounds = tkinter.Spinbox(self.root, textvariable=self.rounds, width=6, from_=1, to=255)
        self.spin_rounds.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.label_key_type = tkinter.Label(self.root, text="Key type:")
        self.label_key_type.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.combo_key_type = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_key_type["values"] = ("Text", "Hex")
        self.combo_key_type.current(0)
        self.combo_key_type.grid(row=2, column=1, padx=5, pady=5)

        self.label_key = tkinter.Label(self.root, text="Key:")
        self.label_key.grid(row=2, column=2, padx=5, pady=5, sticky="w")

        self.entry_key = tkinter.Entry(width=32)
        self.entry_key.grid(row=2, column=3, padx=5, pady=5, sticky="w")
        self.entry_key.focus() # Focus to this widget

        self.label_iv_type = tkinter.Label(self.root, text="IV type:")
        self.label_iv_type.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.combo_iv_type = tkinter.ttk.Combobox(self.root, width=5, state="readonly")
        self.combo_iv_type["values"] = ("Text", "Hex")
        self.combo_iv_type.current(0)
        self.combo_iv_type.grid(row=3, column=1, padx=5, pady=5)

        self.label_iv = tkinter.Label(self.root, text="IV:")
        self.label_iv.grid(row=3, column=2, padx=5, pady=5, sticky="w")

        self.entry_iv = tkinter.Entry(width=32)
        self.entry_iv.grid(row=3, column=3, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=4, column=0, padx=5, pady=5, columnspan=4)

        # Set callback functions
        self.combo_mode.bind('<<ComboboxSelected>>', lambda event: self.combo_mode_selected())
        self.combo_mode.bind("<Return>", lambda event: self.process())
        self.combo_block_size.bind("<Return>", lambda event: self.process())
        self.spin_rounds.bind("<Return>", lambda event: self.process())
        self.combo_key_type.bind("<Return>", lambda event: self.process())
        self.entry_key.bind("<Return>", lambda event: self.process())
        self.combo_iv_type.bind("<Return>", lambda event: self.process())
        self.entry_iv.bind("<Return>", lambda event: self.process())
        self.button.bind("<Return>", lambda event: self.process())

        # These are disabled in the initial state (ECB mode)
        self.combo_iv_type.configure(state = "disabled")
        self.entry_iv.configure(state = "disabled")

    def process(self, **kwargs):
        rc5_block_size = (4, 8, 16)

        mode = self.combo_mode.get()
        block_size = rc5_block_size[self.combo_block_size.current()]
        word_size = block_size * 4
        segment_size = block_size * 8
        key_type = self.combo_key_type.get()
        key = self.entry_key.get()
        iv_type = self.combo_iv_type.get()
        iv = self.entry_iv.get()

        if self.spin_rounds.get() == "":
            tkinter.messagebox.showerror("Error:", message="Rounds must be between 1 and 255.")
            return
        else:
            rounds = int(self.spin_rounds.get())
            if rounds < 1 or rounds > 255:
                tkinter.messagebox.showerror("Error:", message="Rounds must   be between 1 and 255.")
                return

        if key_type == "Hex":
            if re.match("^([0-9A-Fa-f]{2})+$", key):
                key = binascii.a2b_hex(key)
            else:
                tkinter.messagebox.showerror("Error:", message="Key is not in hex format.")
                return
        else:
            key = key.encode()

        if mode in ["CBC", "CFB", "OFB", "CTR"] and iv_type == "Hex":
            if re.match("^([0-9A-Fa-f]{2})+$", iv):
                iv = binascii.a2b_hex(iv)
            else:
                tkinter.messagebox.showerror("Error:", message="IV is not in hex format.")
                return
        else:
            iv = iv.encode()

        if len(key) < 1 or len(key) > 255: # 2040 bits
            tkinter.messagebox.showerror("Error:", message="Key size must be between 1 and 255 bytes.")
            return

        if mode in ["CBC", "CFB", "OFB", "CTR"] and len(iv) != block_size:
            tkinter.messagebox.showerror("Error:", message="IV size must be %d bytes." % block_size)
            return

        try:
            if mode in ["OFB", "CTR"]:
                cipher = refinery.units.crypto.cipher.rc5.rc5(key=key, iv=iv, mode=mode, rounds=rounds, word_size=word_size)
            elif mode == "CFB":
                cipher = refinery.units.crypto.cipher.rc5.rc5(key=key, iv=iv, mode=mode, segment_size=segment_size, rounds=rounds, word_size=word_size)
            elif mode == "CBC":
                cipher = refinery.units.crypto.cipher.rc5.rc5(key=key, iv=iv, padding="pkcs7", mode=mode, rounds=rounds, word_size=word_size)
            elif mode == "ECB":
                cipher = refinery.units.crypto.cipher.rc5.rc5(key=key, padding="pkcs7", mode=mode, rounds=rounds, word_size=word_size)

            ciphertext = cipher.reverse(data=self.data)
        except Exception as e:
            tkinter.messagebox.showerror("Error:", message=e)
            self.root.quit()
            exit(1) # Not encrypted

        sys.stdout.buffer.write(ciphertext)
        self.root.quit()
        exit(0) # Encrypted successfully

    def combo_mode_selected(self):
        mode = self.combo_mode.get()
        if mode == "ECB":
            self.combo_iv_type.configure(state = "disabled")
            self.entry_iv.configure(state = "disabled")
        else:
            self.combo_iv_type.configure(state = "readonly")
            self.entry_iv.configure(state = "normal")

    def rounds_changed(self, *args):
        r = self.rounds.get()
        if not re.match("^([0-9])+$", r) and r != "":
            self.rounds.set("12")

if __name__ == "__main__":
    # Receive data
    data = sys.stdin.buffer.read()

    dialog = RC5EncryptDialog(title="RC5 encrypt", data=data)
    dialog.show()
    exit(1) # Not decrypted
