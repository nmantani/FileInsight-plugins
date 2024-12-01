#
# Dialog for the following plugins:
# Custom base32 decode
# Custom base32 encode
# Custom base58 decode
# Custom base58 encode
# Custom base62 decode
# Custom base62 encode
# Custom base64 decode
# Custom base64 encode
# Custom base85 decode
# Custom base85 encode
# Custom base91 decode
# Custom base91 encode
# Custom base92 decode
# Custom base92 encode
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

sys.path.append("./lib")
import dialog_base

class CustomBASEXXDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])
        digits = kwargs["digits"]

        if digits == "92":
            table = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}~"
        elif digits == "91":
            table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
        elif digits == "85":
            table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
        elif digits == "64":
            table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        elif digits == "62":
            table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        elif digits == "58":
            table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        elif digits == "32":
            table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
        elif digits == "16":
            table = "0123456789ABCDEF"
        else:
            sys.exit(1)

        self.label = tkinter.Label(self.root, text="base%s table:" % digits)
        self.label.grid(row=0, column=0, padx=5, pady=5)

        self.entry = tkinter.Entry(self.root, width=(len(table) + 16))
        self.entry.insert(tkinter.END, table)
        self.entry.grid(row=0, column=1, padx=5, pady=5)
        self.entry.focus() # Focus to this widget

        self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.print_table()))
        self.button.grid(row=0, column=2, padx=5, pady=5)

        # Event handlers for hitting enter key
        self.entry.bind("<Return>", lambda event: self.print_table())
        self.button.bind("<Return>", lambda event: self.print_table())

    # Print entered table to stdout
    def print_table(self):
        print(self.entry.get())
        self.root.quit()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(0)
    else:
        digits = sys.argv[1]
        action = sys.argv[2]

    dialog = CustomBASEXXDialog(title="Custom base%s %s" % (digits, action), digits=digits)
    dialog.show()
