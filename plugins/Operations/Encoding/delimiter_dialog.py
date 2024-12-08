#
# Delimiter setting dialog for the following plugins:
#   Binary data to decimal text
#   Decimal text to binary data
#   Binary data to octal text
#   Octal text to binary data
#
# Copyright (c) 2019, Nobutaka Mantani
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

class DelimiterDialog(dialog_base.DialogBase):
    def __init__(self, **kwargs):
        super().__init__(title=kwargs["title"])

        if "delimiter_menu" in kwargs:
            delimiter_menu = kwargs["delimiter_menu"]
        else:
            delimiter_menu = False

        if "endianness_menu" in kwargs:
            endianness_menu = kwargs["endianness_menu"]
        else:
            endianness_menu = False

        if "single_int_checkbox" in kwargs:
            single_int_checkbox = kwargs["single_int_checkbox"]
        else:
            single_int_checkbox = False

        self.label_delimiter = tkinter.Label(self.root, text="Delimiter:")
        self.combo_delimiter = tkinter.ttk.Combobox(self.root, width=10, state="readonly")
        self.combo_delimiter["values"] = ("Space", "Comma", "Semi-colon", "Colon", "Tab", "LF", "CRLF")
        self.combo_delimiter.current(0)

        self.label_endianness1 = tkinter.Label(self.root, text="endianness:")
        self.combo_endianness = tkinter.ttk.Combobox(self.root, width=10, state="readonly")
        self.combo_endianness["values"] = ("Big", "Little")
        self.combo_endianness.current(0)
        self.label_endianness2 = tkinter.Label(self.root, text="Endianness is applied to multibyte values\n(> 255).", justify="left")

        self.single_int = tkinter.BooleanVar()
        self.single_int.set(False)
        self.checkbox = tkinter.Checkbutton(self.root, variable=self.single_int, text="Convert into single integer value\n(except leading / trailing zeros)", justify="left", command=(lambda: self.single_int_checked()))

        num_rows = 0
        if delimiter_menu:
            self.label_delimiter.grid(row=num_rows, column=0, padx=5, pady=5,  sticky="w")
            self.combo_delimiter.grid(row=num_rows, column=1, padx=5, pady=5, sticky="w")

            if single_int_checkbox or endianness_menu:
                num_rows += 1

        if single_int_checkbox:
            self.checkbox.grid(row=num_rows, column=0, padx=5, pady=5, sticky="w", columnspan=2)
            num_rows += 1

            self.label_endianness1.grid(row=num_rows, column=0, padx=5, pady=5, sticky="w")
            self.label_endianness1.grid_remove()
            self.combo_endianness.grid(row=num_rows, column=1, padx=5, pady=5, sticky="w")
            num_rows += 1

            self.combo_endianness.grid_remove()
            self.label_endianness2.grid(row=num_rows, column=0, padx=5, pady=5, sticky="w", columnspan=2)
            self.label_endianness2.grid_remove()
            num_rows += 1

            self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.print_setting()))
            self.button.grid(row=num_rows, column=0, padx=5, pady=5, columnspan=2)
            self.button.focus() # Focus to this widget
            num_rows += 1
        elif endianness_menu:
            self.label_endianness1.grid(row=num_rows, column=0, padx=5, pady=5, sticky="w")
            self.combo_endianness.grid(row=num_rows, column=1, padx=5, pady=5, sticky="w")
            num_rows += 1

            self.label_endianness2.grid(row=num_rows, column=0, padx=5, pady=5, sticky="w", columnspan=2)
            num_rows += 1

            self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.print_setting()))
            self.button.grid(row=num_rows, column=0, padx=5, pady=5, columnspan=2)
            self.button.focus() # Focus to this widget
            num_rows += 1
        else:
            self.button = tkinter.Button(self.root, text="OK", command=(lambda: self.print_setting()))
            self.button.grid(row=num_rows, column=2, padx=5, pady=5)
            self.button.focus() # Focus to this widget
            num_rows += 1

        # Set callback functions
        self.combo_delimiter.bind("<Return>", lambda event: self.print_setting())
        self.combo_endianness.bind("<Return>", lambda event: self.print_setting())
        self.button.bind("<Return>", lambda event: self.print_setting())

    # Print delimiter setting to stdout
    def print_setting(self):
        print("%s\t%s\t%s" % (self.combo_delimiter.get(), self.combo_endianness.get(), self.single_int.get()))
        self.root.quit()

    def single_int_checked(self):
        if self.single_int.get():
            self.label_endianness1.grid()
            self.label_endianness2.grid()
            self.combo_endianness.grid()
        else:
            self.label_endianness1.grid_remove()
            self.label_endianness2.grid_remove()
            self.combo_endianness.grid_remove()

if __name__ == "__main__":
    delimiter_menu = False
    endianness_menu = False
    single_int_checkbox = False

    if len(sys.argv) > 1 and "-d" in sys.argv[1:]:
        delimiter_menu = True

    if len(sys.argv) > 1 and "-e" in sys.argv[1:]:
        endianness_menu = True

    if len(sys.argv) > 1 and "-s" in sys.argv[1:]:
        single_int_checkbox = True

    dialog = DelimiterDialog(title="Delimiter setting", delimiter_menu=delimiter_menu, endianness_menu=endianness_menu, single_int_checkbox=single_int_checkbox)
    dialog.show()
