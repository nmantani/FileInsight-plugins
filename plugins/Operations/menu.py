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

ops_dict = {}
ops_dict["Basic"] = ("Copy to new file",
                     "Cut binary to clipboard",
                     "Copy binary to clipboard",
                     "Paste binary from clipboard",
                     "Delete before",
                     "Delete after",
                     "Fill",
                     "Invert",
                     "Reverse order",
                     "Swap nibbles",
                     "Swap two bytes",
                     "To upper case",
                     "To lower case",
                     "Swap case")

ops_dict["Compression"] = ("aPLib compress",
                           "aPLib decompress",
                           "Bzip2 compress",
                           "Bzip2 decompress",
                           "Gzip compress",
                           "Gzip decompress",
                           "LZMA compress",
                           "LZMA decompress",
                           "LZNT1 compress",
                           "LZNT1 decompress",
                           "Raw deflate",
                           "Raw inflate",
                           "XZ compress",
                           "XZ decompress")

ops_dict["Crypto"] = ("AES decrypt",
                      "AES encrypt",
                      "ARC2 decrypt",
                      "ARC2 encrypt",
                      "ARC4 decrypt / encrypt",
                      "Blowfish decrypt",
                      "Blowfish encrypt",
                      "ChaCha20 decrypt / encrypt",
                      "DES decrypt",
                      "DES encrypt",
                      "Salsa20 decrypt / encrypt",
                      "Triple DES decrypt",
                      "Triple DES encrypt")

ops_dict["Encoding"] = ("Binary data to hex text",
                        "Hex text to binary data",
                        "Binary data to decimal text",
                        "Decimal text to binary data",
                        "Binary data to octal text",
                        "Octal text to binary data",
                        "Binary data to binary text",
                        "Binary text to binary data",
                        "Custom base64 decode",
                        "Custom base64 encode",
                        "ROT13",
                        "From quoted printable",
                        "To quoted printable")

ops_dict["Misc"] = ("Byte frequency",
                    "File comparison",
                    "Hash values",
                    "Send to")

ops_dict["Parsing"] = ("Binwalk scan",
                       "File type",
                       "Find PE file",
                       "Show metadata",
                       "Strings")

ops_dict["Search"] = ("Regex search",
                      "Replace",
                      "XOR hex search",
                      "XOR text search",
                      "YARA scan")

ops_dict["XOR"] = ("Decremental XOR",
                   "Incremental XOR",
                   "Null-preserving XOR",
                   "XOR with next byte",
                   "Guess 256 byte XOR keys",
                   "Visual Decrypt",
                   "Visual Encrypt")
exit_value = -1

root = tkinter.Tk()
root.bind("<FocusOut>", lambda x:root.quit())

# Adjust menu position
x = int(sys.argv[1])
if x > 10:
    x = x - 10
y = int(sys.argv[2])
if y > 10:
    y = y - 10

# Add menu items
categories = ("Basic", "Compression", "Crypto", "Encoding", "Misc", "Parsing", "Search", "XOR")
offset = 0
menu = tkinter.Menu(root, tearoff=False)
menu_dict = {}

for c in categories:
    menu_dict[c] = tkinter.Menu(menu, tearoff=False)
    menu.add_cascade(label=c, menu=menu_dict[c])

    for i in range(0, len(ops_dict[c])):
        def index(offset=offset, i=i):
            global exit_value
            exit_value = offset + i
            root.quit()

        menu_dict[c].add_command(label=ops_dict[c][i], command=index)

    offset += len(ops_dict[c])

root.withdraw() # Hide root window
menu.post(x, y) # Show popup menu

root.mainloop()

sys.exit(exit_value) # index number of operation is returned as exit value
