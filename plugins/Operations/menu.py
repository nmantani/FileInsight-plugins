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
tooltip_dict = {}
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
tooltip_dict["Basic"] = ("Copy selected region (the whole file if not selected) to new file",
                         "Cut binary data of selected region to clipboard as hex-encoded text",
                         "Copy binary data of selected region to clipboard as hex-encoded text",
                         "Paste binary data (converted from hex-encoded text) from clipboard",
                         "Delete all region before current cursor position",
                         "Delete all region after current cursor position",
                         "Fill selected region with specified hex pattern",
                         "Invert bits of selected region",
                         "Reverse order of selected region",
                         "Swap each pair of nibbles of selected region",
                         "Swap each pair of bytes of selected region",
                         "Convert text to upper case of selected region",
                         "Convert text to lower case of selected region",
                         "Swap case of selected region")

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
tooltip_dict["Compression"] = ("Compress selected region with aPLib compression library",
                               "Decompress selected region with aPLib compression library",
                               "Compress selected region with bzip2 algorithm",
                               "Decompress selected region with bzip2 algorithm",
                               "Compress selected region with gzip format",
                               "Decompress selected gzip compressed region",
                               "Compress selected region with LZMA algorithm",
                               "Decompress selected region with LZMA algorithm",
                               "Compress selected region with LZNT1 algorithm",
                               "Decompress selected region with LZNT1 algorithm",
                               "Compress selected region with Deflate algorithm without\nheader and checksum (Equivalent to gzdeflate() in PHP language)",
                               "Decompress selected Deflate compressed region that does\nnot have header and checksum (Equivalent to gzinflate() in PHP language)",
                               "Compress selected region with XZ format",
                               "Decompress selected XZ compressed region")

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
tooltip_dict["Crypto"] = ("Decrypt selected region with AES",
                          "Encrypt selected region with AES",
                          "Decrypt selected region with ARC2 (Alleged RC2)",
                          "Encrypt selected region with ARC2 (Alleged RC2)",
                          "Decrypt / encrypt selected region with ARC4 (Alleged RC4)",
                          "Decrypt selected region with Blowfish",
                          "Encrypt selected region with Blowfish",
                          "Decrypt / encrypt selected region with ChaCha20",
                          "Decrypt selected region with DES",
                          "Encrypt selected region with DES",
                          "Decrypt / encrypt selected region with Salsa20",
                          "Decrypt selected region with Triple DES",
                          "Encrypt selected region with Triple DES")

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
tooltip_dict["Encoding"] = ("Convert binary of selected region into hex text",
                            "Convert hex text of selected region into binary",
                            "Convert binary of selected region into decimal text",
                            "Convert decimal text of selected region into binary data",
                            "Convert binary of selected region into octal text",
                            "Convert octal text of selected region into binary data",
                            "Convert binary of selected region into binary text",
                            "Convert binary text of selected region into binary data",
                            "Decode selected region with custom base64 table",
                            "Encode selected region with custom base64 table",
                            "Rotate alphabet characters in selected region by the\nspecified amount (default: 13)",
                            "Decode selected region as quoted printable text",
                            "Encode selected region into quoted printable text")

ops_dict["Misc"] = ("Byte frequency",
                    "File comparison",
                    "Hash values",
                    "Send to")
tooltip_dict["Misc"] = ("Show byte frequency of selected region\n(the whole file if not selected)",
                        "Compare contents of two files",
                        "Calculate MD5, SHA1, SHA256 hash values of selected region\n(the whole file if not selected)",
                        "Send selected region (the whole file if not selected) to other programs")

ops_dict["Parsing"] = ("Binwalk scan",
                       "File type",
                       "Find PE file",
                       "Show metadata",
                       "Strings")
tooltip_dict["Parsing"] = ("Scan selected region (the whole file if not selected)\nto find embedded files",
                           "Identify file type of selected region\n(the whole file if not selected)",
                           "Find PE file from selected region\n(the whole file if not selected)",
                           "Show metadata of selected region\n(the whole file if not selected) with ExifTool",
                           "Extract text strings from selected region\n(the whole file if not selected)")

ops_dict["Search"] = ("Regex search",
                      "Replace",
                      "XOR hex search",
                      "XOR text search",
                      "YARA scan")
tooltip_dict["Search"] = ("Search with regular expression in selected region\n(the whole file if not selected)",
                          "Replace matched data in selected region\n(the whole file if not selected) with specified data",
                          "Search XORed / bit-rotated data in selected region\n(the whole file if not selected)",
                          "Search XORed / bit-rotated string in selected region\n(the whole file if not selected)",
                          "Scan selected region (the whole file if not selected)\nwith YARA.")

ops_dict["XOR"] = ("Decremental XOR",
                   "Incremental XOR",
                   "Null-preserving XOR",
                   "XOR with next byte",
                   "Guess 256 byte XOR keys",
                   "Visual Decrypt",
                   "Visual Encrypt")
tooltip_dict["XOR"] = ("XOR selected region while decrementing XOR key",
                       "XOR selected region while incrementing XOR key",
                       "XOR selected region while skipping null bytes and XOR key itself",
                       "XOR selected region while using next byte as XOR key",
                       "Guess 256 byte XOR keys from selected region\n(the whole file if not selected) based on the byte frequency",
                       "Encode selected region with visual encrypt algorithm that is used by Zeus trojan",
                       "Decode selected region with visual decrypt algorithm that is used by Zeus trojan")

# Global variables for menu callbacks
exit_value = -1
tooltip_window = None

root = tkinter.Tk()
root.bind("<FocusOut>", lambda x:root.quit()) # Exit on focusout

# Adjust menu position
x = int(sys.argv[1])
if x > 10:
    x = x - 10
y = int(sys.argv[2])
if y > 10:
    y = y - 10

# Add menu items
categories = ("Basic", "Compression", "Crypto", "Encoding", "Misc", "Parsing", "Search", "XOR")
index_start = 0
menu = tkinter.Menu(root, tearoff=False)
menu_dict = {}

for c in categories:
    menu_dict[c] = tkinter.Menu(menu, tearoff=False)

    # Callback to show tooltip of menu items
    def menuselect_callback(event, tooltip_dict=tooltip_dict[c]):
        global tooltip_window
        # Ignore events when the menu is opened or closed
        if event.y != 0:
            # If tooltip is shown, hide it
            if tooltip_window:
                tooltip_window.destroy()
                tooltip_window = None

            tooltip_window = tkinter.Toplevel()

            # Adjust tooltip position
            if tooltip_window.winfo_pointerx() + 400 > tooltip_window.winfo_screenwidth():
                tooltip_x = tooltip_window.winfo_pointerx() - 400
            else:
                tooltip_x = tooltip_window.winfo_pointerx() + 120
            if tooltip_window.winfo_pointery() + 20 > tooltip_window.winfo_screenheight():
                tooltip_y = tooltip_window.winfo_pointery() - 30
            else:
                tooltip_y = tooltip_window.winfo_pointery() + 10

            tooltip_window.wm_overrideredirect(True) # Do not show window toolbar
            tooltip_window.wm_geometry("+%d+%d" % (tooltip_x, tooltip_y))
            label = tkinter.Label(tooltip_window, text=tooltip_dict[event.widget.index("active")], justify=tkinter.LEFT, background="#ffffff")
            label.pack()
            tooltip_window.attributes("-topmost", True) # Raise tooltip window to the top

    menu_dict[c].bind("<<MenuSelect>>", menuselect_callback)
    menu.add_cascade(label=c, menu=menu_dict[c])

    for i in range(0, len(ops_dict[c])):
        # When a menu item is clicked, exit_value is set to the corresponding index number of operation.
        def menuclick_callback(index_start=index_start, i=i):
            global exit_value
            exit_value = index_start + i
            root.quit()

        menu_dict[c].add_command(label=ops_dict[c][i], command=menuclick_callback)

    index_start += len(ops_dict[c])

root.withdraw() # Hide root window
menu.post(x, y) # Show popup menu

root.mainloop()

sys.exit(exit_value) # index number of operation is returned as exit value
