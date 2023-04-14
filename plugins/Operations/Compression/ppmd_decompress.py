#
# PPMd decompress - Decompress selected region with PPMd algorithm
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

import re
import sys
import tkinter
import tkinter.ttk

sys.path.append("./lib")
import dialog_base

try:
    import pyppmd
except ImportError:
    exit(-1) # pyppmd is not installed

class PPMDDecompressDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label_version = tkinter.Label(self.root, text="PPMd version:")
        self.label_version.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_version = tkinter.ttk.Combobox(self.root, width=12, state="readonly")
        self.combo_version["values"] = ("7 (version H)", "8 (version I)")
        self.combo_version.current(0)
        self.combo_version.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.label_order = tkinter.Label(self.root, text="Model order (2-64):")
        self.label_order.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.order = tkinter.StringVar()
        self.order.set("6")
        self.order.trace("w", self.order_changed)
        self.spin_order = tkinter.Spinbox(self.root, textvariable=self.order, width=4, from_=2, to=64)
        self.spin_order.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.label_description = tkinter.Label(self.root, text="7-zip uses the following values by default:\nFor .7z files: PPMd version -> 7, Model order -> 6\nFor .zip files: PPMd version -> 8, Model order -> 8", justify="left")
        self.label_description.grid(row=2, column=0, padx=5, pady=0, columnspan=2, sticky="w")

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.process()))
        self.button.grid(row=3, column=0, padx=5, pady=5, columnspan=2)
        self.button.focus() # Focus to this widget

        # Set callback functions
        self.combo_version.bind('<<ComboboxSelected>>', lambda event: self.combo_version_changed())

        for x in (self.combo_version, self.spin_order, self.button):
            x.bind("<Return>", lambda event: self.process())

    def process(self, **kwargs):
        self.root.withdraw()

        data = sys.stdin.buffer.read()

        version = self.combo_version.get()
        order = int(self.spin_order.get())

        mem = 32 << 20 # 32 MiB

        try:
            if version == "8 (version I)":
                decoder = pyppmd.Ppmd8Decoder(order, mem)
                decompressed = decoder.decode(data, -1)
            else:
                decoder = pyppmd.Ppmd7Decoder(order, mem)
                decompressed = decoder.decode(data, 2**31 - 1) # About 2GiB

            sys.stdout.buffer.write(decompressed)

            if version == "7 (version H)":
                print("NOTE: The decompressed data may be redundant or truncated if the compressed data does not have an end mark.", file=sys.stderr)
        except Exception as e:
            print(e, file=sys.stderr)
            exit(1)

        self.root.quit()

    def combo_version_changed(self):
        # Set order value to default that is used by 7-Zip
        if self.combo_version.get() == "8 (version I)":
            self.order.set("8")
        else: # 7 (version H)
            self.order.set("6")

    def order_changed(self, *args):
        if not re.match("^-?([0-9])+$", self.order.get()):
            self.order.set("6")
        elif int(self.order.get()) < 2:
            self.order.set("2")
        elif int(self.order.get()) > 64:
            self.order.set("64")

if __name__ == "__main__":
    dialog = PPMDDecompressDialog(title="PPMd compress")
    dialog.show()
