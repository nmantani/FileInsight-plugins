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
                     "Bookmark",
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
tooltip_dict["Basic"] = ("Copy selected region (the whole file if not selected) to a new file",
                         "Bookmark selected region with specified comment and color",
                         "Cut binary data of selected region to clipboard as hex-encoded text",
                         "Copy binary data of selected region to clipboard as hex-encoded text",
                         "Paste binary data (converted from hex-encoded text) from clipboard",
                         "Delete all region before the current cursor position",
                         "Delete all region after the current cursor position",
                         "Fill selected region with specified hex pattern",
                         "Invert bits of selected region",
                         "Reverse order of selected region",
                         "Swap each pair of nibbles of selected region",
                         "Swap each pair of bytes of selected region",
                         "Convert text to upper case of selected region",
                         "Convert text to lower case of selected region",
                         "Swap case of selected region")

ops_dict["Compress"] = ("aPLib",
                        "Bzip2",
                        "Gzip",
                        "LZ4",
                        "LZMA",
                        "LZNT1",
                        "LZO",
                        "PPMd",
                        "QuickLZ",
                        "Raw deflate",
                        "XZ",
                        "zlib (deflate)",
                        "Zstandard")
tooltip_dict["Compress"] = ("Compress selected region with aPLib compression library",
                            "Compress selected region with bzip2 algorithm",
                            "Compress selected region with gzip format",
                            "Compress selected region with LZ4 algorithm",
                            "Compress selected region with LZMA algorithm",
                            "Compress selected region with LZNT1 algorithm",
                            "Compress selected region with LZO algorithm",
                            "Compress selected region with PPMd algorithm",
                            "Compress selected region with QuickLZ compression library",
                            "Compress selected region with Deflate algorithm without\nheader and checksum (equivalent to gzdeflate() in PHP language)",
                            "Compress selected region with XZ format",
                            "Compress selected region with zlib (Deflate algorithm)",
                            "Compress selected region with Zstandard algorithm")

ops_dict["Decompress"] = ("aPLib",
                           "Bzip2",
                           "Gzip",
                           "LZ4",
                           "LZMA",
                           "LZNT1",
                           "LZO",
                           "PPMd",
                           "QuickLZ",
                           "Raw inflate",
                           "XZ",
                           "zlib (inflate)",
                           "Zstandard")
tooltip_dict["Decompress"] = ("Decompress selected region with aPLib compression library",
                              "Decompress selected region with bzip2 algorithm",
                              "Decompress selected gzip-compressed region",
                              "Decompress selected region with LZ4 algorithm",
                              "Decompress selected region with LZMA algorithm",
                              "Decompress selected region with LZNT1 algorithm",
                              "Decompress selected region with LZO algorithm",
                              "Decompress selected region with PPMd algorithm",
                              "Decompress selected region with QuickLZ compression library",
                              "Decompress selected Deflate compressed region that does\nnot have header and checksum (equivalent to gzinflate() in PHP language)",
                              "Decompress selected XZ compressed region",
                              "Decompress selected region with zlib (Deflate algorithm)",
                              "Decompress selected region with Zstandard algorithm")

ops_dict["Decrypt"] = ("AES",
                       "ARC2",
                       "ARC4",
                       "Blowfish",
                       "ChaCha20",
                       "DES",
                       "Salsa20",
                       "TEA",
                       "Triple DES",
                       "XTEA")
tooltip_dict["Decrypt"] = ("Decrypt selected region with AES",
                          "Decrypt selected region with ARC2 (Alleged RC2)",
                          "Decrypt selected region with ARC4 (Alleged RC4)",
                          "Decrypt selected region with Blowfish",
                          "Decrypt selected region with ChaCha20",
                          "Decrypt selected region with DES",
                          "Decrypt selected region with Salsa20",
                          "Decrypt selected region with TEA (Tiny Encryption Algorithm)",
                          "Decrypt selected region with Triple DES",
                          "Decrypt selected region with XTEA (eXtended Tiny Encryption Algorithm)")

ops_dict["Encrypt"] = ("AES",
                       "ARC2",
                       "ARC4",
                       "Blowfish",
                       "ChaCha20",
                       "DES",
                       "Salsa20",
                       "TEA",
                       "Triple DES",
                       "XTEA")
tooltip_dict["Encrypt"] = ("Encrypt selected region with AES",
                          "Encrypt selected region with ARC2 (Alleged RC2)",
                          "Encrypt selected region with ARC4 (Alleged RC4)",
                          "Encrypt selected region with Blowfish",
                          "Encrypt selected region with ChaCha20",
                          "Encrypt selected region with DES",
                          "Encrypt selected region with Salsa20",
                          "Encrypt selected region with TEA (Tiny Encryption Algorithm)",
                          "Encrypt selected region with Triple DES",
                          "Encrypt selected region with XTEA (eXtended Tiny Encryption Algorithm)")

ops_dict["Decode"] = ("Hex text to binary data",
                      "Decimal text to binary data",
                      "Octal text to binary data",
                      "Binary text to binary data",
                      "Custom base16",
                      "Custom base32",
                      "Custom base58",
                      "Custom base64",
                      "Custom base85",
                      "Protobuf decode",
                      "From quoted printable",
                      "Unicode unescape",
                      "URL decode")
tooltip_dict["Decode"] = ("Convert hex text of selected region into binary",
                          "Convert decimal text of selected region into binary data",
                          "Convert octal text of selected region into binary data",
                          "Convert binary text of selected region into binary data",
                          "Decode selected region with custom base16 table",
                          "Decode selected region with custom base32 table",
                          "Decode selected region with custom base58 table",
                          "Decode selected region with custom base64 table",
                          "Decode selected region with custom base85 table",
                          "Decode selected region as Protocol Buffers serialized data without .proto files",
                          "Decode selected region as quoted printable text",
                          "Unescape Unicode escape sequence of selected region",
                          "Decode selected region as percent-encoded text\nthat is used by URL")

ops_dict["Encode"] = ("Binary data to hex text",
                      "Binary data to decimal text",
                      "Binary data to octal text",
                      "Binary data to binary text",
                      "Custom base16",
                      "Custom base32",
                      "Custom base58",
                      "Custom base64",
                      "Custom base85",
                      "ROT13",
                      "To quoted printable",
                      "Unicode escape",
                      "URL encode")
tooltip_dict["Encode"] = ("Convert binary of selected region into hex text",
                          "Convert binary of selected region into decimal text",
                          "Convert binary of selected region into octal text",
                          "Convert binary of selected region into binary text",
                          "Encode selected region with custom base16 table",
                          "Encode selected region with custom base32 table",
                          "Encode selected region with custom base58 table",
                          "Encode selected region with custom base64 table",
                          "Encode selected region with custom base85 table",
                          "Rotate alphabet characters in selected region by the\nspecified amount (default: 13)",
                          "Encode selected region into quoted printable text",
                          "Escape Unicode characters of selected region",
                          "Encode selected region into percent-encoded text\nthat is used by URL")

ops_dict["Misc"] = ("Emulate code",
                    "File comparison",
                    "Hash values",
                    "Send to")
tooltip_dict["Misc"] = ("Emulate selected region as an executable or shellcode\nwith Qiling Framework (the whole file if not selected)",
                        "Compare contents of two files",
                        "Calculate MD5, SHA1, SHA256, ssdeep, imphash, impfuzzy hash values of\nselected region (the whole file if not selected)",
                        "Send selected region (the whole file if not selected) to other programs")

ops_dict["Parsing"] = ("Binwalk scan",
                       "Disassemble",
                       "File type",
                       "Find PE file",
                       "Parse file structure",
                       "Show metadata",
                       "Strings")
tooltip_dict["Parsing"] = ("Scan selected region (the whole file if not selected)\nto find embedded files",
                           "Disassemble selected region\n(the whole file if not selected)",
                           "Identify file type of selected region\n(the whole file if not selected)",
                           "Find PE file from selected region\n(the whole file if not selected)",
                           "Parse file structure of selected region\n(the whole file if not selected) with Kaitai Struct",
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

ops_dict["Visualization"] = ("Bitmap view",
                             "Byte histogram",
                             "Entropy graph")
tooltip_dict["Visualization"] = ("Visualize the whole file as a bitmap representation",
                                 "Show byte histogram of selected region\n(the whole file if not selected)",
                                 "Show entropy graph of selected region\n(the whole file if not selected)")

ops_dict["XOR"] = ("Decremental XOR",
                   "Incremental XOR",
                   "Null-preserving XOR",
                   "XOR with next byte",
                   "Guess multibyte XOR keys",
                   "Visual Decrypt",
                   "Visual Encrypt")
tooltip_dict["XOR"] = ("XOR selected region while decrementing XOR key",
                       "XOR selected region while incrementing XOR key",
                       "XOR selected region while skipping null bytes and XOR key itself",
                       "XOR selected region while using next byte as XOR key",
                       "Guess multibyte XOR keys from selected region (the whole file if not selected)\nbased on revealed keys that are XORed with 0x00",
                       "Decode selected region with visual encrypt algorithm\nthat is used by Zeus trojan",
                       "Encode selected region with visual decrypt algorithm\nthat is used by Zeus trojan")

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
categories = ("Basic", "Compress", "Decompress", "Decrypt", "Encrypt", "Decode", "Encode", "Misc", "Parsing", "Search", "Visualization", "XOR")

# Dictionary for parent categories
parent_dict = {}
parent_dict["Compress"] = "Compression"
parent_dict["Decompress"] = "Compression"
parent_dict["Decrypt"] = "Crypto"
parent_dict["Encrypt"] = "Crypto"
parent_dict["Decode"] = "Encoding"
parent_dict["Encode"] = "Encoding"

index_start = 0
menu = tkinter.Menu(root, tearoff=False)
menu_dict = {}

for c in categories:
    # For categories that do not have sub-categories
    if c not in ("Compress", "Decompress", "Decrypt", "Encrypt", "Decode", "Encode"):
        menu_dict[c] = tkinter.Menu(menu, tearoff=False)

    # Callback to show tooltip of menu items
    def menuselect_callback(event, tooltip_dict=tooltip_dict[c]):
        global tooltip_window
        # Ignore events when the menu is opened or closed
        if event.y != 0 and event.widget.index("active") != None:
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

    if c in ("Compress", "Decrypt", "Decode"):
        # sub-category menus will be added to this item
        menu_dict[parent_dict[c]] = tkinter.Menu(menu, tearoff=False)
        menu.add_cascade(label=parent_dict[c], menu=menu_dict[parent_dict[c]])

        menu_dict[c] = tkinter.Menu(menu_dict[parent_dict[c]], tearoff=False)
        menu_dict[c].bind("<<MenuSelect>>", menuselect_callback)
        menu_dict[parent_dict[c]].add_cascade(label=c, menu=menu_dict[c])
    elif c in ("Decompress", "Encrypt", "Encode"):
        menu_dict[c] = tkinter.Menu(menu_dict[parent_dict[c]], tearoff=False)
        menu_dict[c].bind("<<MenuSelect>>", menuselect_callback)
        menu_dict[parent_dict[c]].add_cascade(label=c, menu=menu_dict[c])
    else:
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
