#
# Unicode escape format setting dialog for the following plugins:
#   Unicode escape
#   Unicode unescape
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
import tkinter.ttk

sys.path.append("./lib")
import dialog_base

class UnicodeFormatDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        self.label_format = tkinter.Label(self.root, text="Unicode escape format:")
        self.label_format.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.combo_format = tkinter.ttk.Combobox(self.root, width=40, state="readonly")
        self.combo_format["values"] = ("\\uXXXX    (Java, JavaScript)",
                                "\\uXXXX and \\UXXXXXXXX    (C, Python)",
                                "\\u{XXXX}    (JavaScript ES6+, PHP 7+)",
                                "`u{XXXX}    (PowerShell 6+)",
                                "%uXXXX    (Legacy JavaScript)",
                                "U+XXXX    (Unicode code point)")
        self.combo_format.current(0)
        self.combo_format.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.label_encoding = tkinter.Label(self.root, text=kwargs["label_text"])

        self.label_encoding.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.combo_encoding = tkinter.ttk.Combobox(self.root, width=10, state="readonly")
        self.combo_encoding["values"] = ("UTF-8", "UTF-16LE", "UTF-16BE")
        self.combo_encoding.current(0)
        self.combo_encoding.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.button = tkinter.Button(self.root, text='OK', command=(lambda: self.print_setting()))
        self.button.grid(row=2, column=0, padx=5, pady=5, columnspan=3)
        self.button.focus() # Focus to this widget

        # Set callback functions
        for x in (self.combo_format, self.combo_encoding, self.button):
            x.bind("<Return>", lambda event: self.print_setting())

    # Print setting to stdout
    def print_setting(self):
        escape_format = {"\\uXXXX    (Java, JavaScript)": "\\u",
                        "\\uXXXX and \\UXXXXXXXX    (C, Python)": "\\U",
                        "\\u{XXXX}    (JavaScript ES6+, PHP 7+)": "\\u{",
                        "`u{XXXX}    (PowerShell 6+)": "`u",
                        "%uXXXX    (Legacy JavaScript)": "%u",
                        "U+XXXX    (Unicode code point)": "U+"}
        print("%s\t%s" % (escape_format[self.combo_format.get()], self.combo_encoding.get()))
        self.root.quit()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "-e":
        label_text = "Input encoding:"
    elif len(sys.argv) > 1 and sys.argv[1] == "-u":
        label_text = "Output encoding:"
    else:
        label_text = "Encoding:"

    dialog = UnicodeFormatDialog(title="Unicode escape/unescape format setting", label_text=label_text)
    dialog.show()
