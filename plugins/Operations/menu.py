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

import distutils.version
import subprocess
import sys
import tkinter
import tkinter.messagebox
import webbrowser
import winreg

def check_update(root, version):
    try:
        import requests
    except ImportError:
        sys.exit(-2) # requests is not installed

    api_url = "https://api.github.com/repos/nmantani/FileInsight-plugins/releases/latest"
    try:
        # Get proxy server settings
        reg_key = winreg.OpenKeyEx(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        num_values = winreg.QueryInfoKey(reg_key)[1]

        proxy_enable = 0
        proxy_server = ""
        for i in range(0, num_values):
            value_name = winreg.EnumValue(reg_key, i)[0]
            if value_name == "ProxyEnable":
                proxy_enable, regtype = winreg.QueryValueEx(reg_key, "ProxyEnable")

            if value_name == "ProxyServer":
                proxy_server, regtype = winreg.QueryValueEx(reg_key, "ProxyServer")

        winreg.CloseKey(reg_key)

        if proxy_enable == 1 and proxy_server != "":
            if "=" in proxy_server:
                # Example of proxy_server: http=10.0.0.1:8080;https=10.0.0.1:8080;ftp=10.0.0.1:8080;socks=10.0.0.1:8080
                proxy_list = proxy_server.split(";")
                proxies = {}
                for p in proxy_list:
                    if "http=" in p or "https=" in p:
                        (proto, server) = p.split("=")
                        proxies[proto] = "http://%s" % server
            else:
                proxies = {
                    "http": "http://" + proxy_server,
                    "https": "http://" + proxy_server
                }

            r = requests.get(api_url, proxies=proxies)
        else:
            r = requests.get(api_url)
    except Exception as e:
        tkinter.messagebox.showerror("Error:", message=e)
        sys.exit(-1) # root.quit() cannot be used

    if r.status_code == 200:
        json_data = r.json()
        latest_version = json_data["tag_name"][1:]

        if distutils.version.StrictVersion(latest_version) > distutils.version.StrictVersion(version):
            ret = tkinter.messagebox.askyesno("Confirmation", "New version %s is available.\r\nWould you like to update?" % latest_version)
            if ret == True:
                tkinter.messagebox.showinfo(None, message="Update PowerShell script (https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1) will be executed.")

                try:
                    if proxy_enable == 1 and proxy_server != "":
                        p = subprocess.Popen(args=["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-exec", "bypass", "-command", "$web_client = New-Object System.Net.WebClient; $web_client.Proxy = New-Object System.Net.WebProxy('%s', $true); $script = ($web_client.DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1')); &([scriptblock]::Create($script)) -update; Read-Host 'Please hit Enter key to close this window'" % proxies["http"]], creationflags=subprocess.CREATE_NEW_CONSOLE)
                    else:
                        p = subprocess.Popen(args=["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-exec", "bypass", "-command", "& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))) -update; Read-Host 'Please hit Enter key to close this window'"], creationflags=subprocess.CREATE_NEW_CONSOLE)
                except Exception as e:
                    tkinter.messagebox.showerror("Error:", message=e)
                    sys.exit(-1) # root.quit() cannot be used
        elif distutils.version.StrictVersion(latest_version) == distutils.version.StrictVersion(version):
            tkinter.messagebox.showinfo(None, message="You are using the latest version %s." % version)
        else:
            tkinter.messagebox.showinfo(None, message="You are using development version %s (newer than the latest release version %s)." % (version, latest_version))

    root.quit()

def show_version_dialog(root, version):
    root.unbind("<FocusOut>") # Remove focusout handler

    dialog = tkinter.Toplevel()
    dialog.title("Version information")
    dialog.protocol("WM_DELETE_WINDOW", lambda r=root: r.quit())

    label_version = tkinter.Label(dialog, text="FileInsight-plugins version %s" % version)
    label_version.grid(row=0, column=0, padx=15, pady=5, sticky="w")

    label_copyright = tkinter.Label(dialog, text="Copyright (c) 2012-2023, Nobutaka Mantani\nAll rights reserved.", justify="left")
    label_copyright.grid(row=1, column=0, padx=15, pady=5, sticky="w")

    label_link = tkinter.Label(dialog, text="https://github.com/nmantani/FileInsight-plugins/", fg="#0000ff", justify="left", cursor="hand2")
    label_link.grid(row=2, column=0, padx=15, pady=5, sticky="w")
    label_link.bind("<Button-1>", lambda event: webbrowser.open_new_tab("https://github.com/nmantani/FileInsight-plugins/"))

    button = tkinter.Button(dialog, text="OK", command=lambda r=root: r.quit())
    button.grid(row=3, column=0, padx=15, pady=5, sticky="s")
    button.bind("<Return>", lambda event, r=root: r.quit())

    # Adjust window position
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    dialog.update_idletasks() # Necessary to get width and height of the window
    ww = dialog.winfo_width()
    wh = dialog.winfo_height()
    dialog.geometry('+%d+%d' % ((sw/2) - (ww/2), (sh/2) - (wh/2)))

    button.focus() # Focus to this widget

if len(sys.argv) < 4:
    print("Usage: menu.py pos_x pos_y version")
    sys.exit(0)

ops_dict = {}
tooltip_dict = {}
ops_dict["Basic"] = ("Copy to new file",
                     "Switch file tabs",
                     "Bookmark",
                     "Cut binary to clipboard",
                     "Copy binary to clipboard",
                     "Paste binary from clipboard",
                     "Delete before",
                     "Delete after",
                     "Fill",
                     "Invert",
                     "Reverse order",
                     "Change endianness",
                     "Swap nibbles",
                     "Swap two bytes",
                     "To upper case",
                     "To lower case",
                     "Swap case")
tooltip_dict["Basic"] = ("Copy selected region (the whole file if not selected) to a new file",
                         "Switch file tabs with a listbox",
                         "Bookmark selected region with specified comment and color",
                         "Cut binary data of selected region to clipboard as hex-encoded text",
                         "Copy binary data of selected region to clipboard as hex-encoded text",
                         "Paste binary data (converted from hex-encoded text) from clipboard",
                         "Delete all region before the current cursor position",
                         "Delete all region after the current cursor position",
                         "Fill selected region with specified hex pattern",
                         "Invert bits of selected region",
                         "Reverse order of selected region",
                         "Change endianness of selected region",
                         "Swap each pair of nibbles of selected region",
                         "Swap each pair of bytes of selected region",
                         "Convert text to upper case of selected region",
                         "Convert text to lower case of selected region",
                         "Swap case of selected region")

ops_dict["Compress"] = ("aPLib",
                        "Brotli",
                        "Bzip2",
                        "Gzip",
                        "LZ4",
                        "LZF",
                        "LZFSE",
                        "lzip",
                        "LZJB",
                        "LZMA",
                        "LZNT1",
                        "LZO",
                        "LZRW1/KH",
                        "PPMd",
                        "QuickLZ",
                        "Raw deflate",
                        "Snappy",
                        "XZ",
                        "zlib (deflate)",
                        "Zstandard")
tooltip_dict["Compress"] = ("Compress selected region with aPLib compression library",
                            "Compress selected region with Brotli algorithm",
                            "Compress selected region with bzip2 algorithm",
                            "Compress selected region with gzip format",
                            "Compress selected region with LZ4 algorithm",
                            "Compress selected region with LZF algorithm",
                            "Compress selected region with LZFSE algorithm",
                            "Compress selected region with lzip format",
                            "Compress selected region with LZJB algorithm",
                            "Compress selected region with LZMA algorithm",
                            "Compress selected region with LZNT1 algorithm",
                            "Compress selected region with LZO algorithm",
                            "Compress selected region with LZRW1/KH algorithm",
                            "Compress selected region with PPMd algorithm",
                            "Compress selected region with QuickLZ compression library",
                            "Compress selected region with Deflate algorithm without\nheader and checksum (equivalent to gzdeflate() in PHP language)",
                            "Compress selected region with Snappy compression library",
                            "Compress selected region with XZ format",
                            "Compress selected region with zlib (Deflate algorithm)",
                            "Compress selected region with Zstandard algorithm")

ops_dict["Decompress"] = ("aPLib",
                           "Brotli",
                           "Bzip2",
                           "Gzip",
                           "LZ4",
                           "LZF",
                           "LZFSE",
                           "lzip",
                           "LZJB",
                           "LZMA",
                           "LZNT1",
                           "LZO",
                           "LZRW1/KH",
                           "PPMd",
                           "QuickLZ",
                           "Raw inflate",
                           "Snappy",
                           "XZ",
                           "zlib (inflate)",
                           "Zstandard")
tooltip_dict["Decompress"] = ("Decompress selected region with aPLib compression library",
                              "Decompress selected region with Brotli algorithm",
                              "Decompress selected region with bzip2 algorithm",
                              "Decompress selected gzip-compressed region",
                              "Decompress selected region with LZ4 algorithm",
                              "Decompress selected region with LZF algorithm",
                              "Decompress selected region with LZFSE algorithm",
                              "Decompress selected lzip compressed region",
                              "Decompress selected region with LZJB algorithm",
                              "Decompress selected region with LZMA algorithm",
                              "Decompress selected region with LZNT1 algorithm",
                              "Decompress selected region with LZO algorithm",
                              "Decompress selected region with LZRW1/KH algorithm",
                              "Decompress selected region with PPMd algorithm",
                              "Decompress selected region with QuickLZ compression library",
                              "Decompress selected Deflate compressed region that does\nnot have header and checksum (equivalent to gzinflate() in PHP language)",
                              "Decompress selected region with Snappy compression library",
                              "Decompress selected XZ compressed region",
                              "Decompress selected region with zlib (Deflate algorithm)",
                              "Decompress selected region with Zstandard algorithm")

ops_dict["Decrypt"] = ("AES",
                       "Blowfish",
                       "CAST-128",
                       "Camellia",
                       "ChaCha20",
                       "DES",
                       "RC2",
                       "RC4",
                       "RC5",
                       "RC6",
                       "Salsa20",
                       "TEA",
                       "Triple DES",
                       "XTEA",
                       "XXTEA")
tooltip_dict["Decrypt"] = ("Decrypt selected region with AES",
                          "Decrypt selected region with Blowfish",
                          "Decrypt selected region with CAST-128",
                          "Decrypt selected region with Camellia",
                          "Decrypt selected region with ChaCha20",
                          "Decrypt selected region with DES",
                          "Decrypt selected region with RC2",
                          "Decrypt selected region with RC4",
                          "Decrypt selected region with RC5",
                          "Decrypt selected region with RC6",
                          "Decrypt selected region with Salsa20",
                          "Decrypt selected region with TEA\n(Tiny Encryption Algorithm)",
                          "Decrypt selected region with Triple DES",
                          "Decrypt selected region with XTEA\n(eXtended Tiny Encryption Algorithm)",
                          "Decrypt selected region with XXTEA\n(Corrected Block Tiny Encryption Algorithm)")

ops_dict["Encrypt"] = ("AES",
                       "Blowfish",
                       "CAST-128",
                       "Camellia",
                       "ChaCha20",
                       "DES",
                       "RC2",
                       "RC4",
                       "RC5",
                       "RC6",
                       "Salsa20",
                       "TEA",
                       "Triple DES",
                       "XTEA",
                       "XXTEA")
tooltip_dict["Encrypt"] = ("Encrypt selected region with AES",
                          "Encrypt selected region with Blowfish",
                          "Encrypt selected region with CAST-128",
                          "Encrypt selected region with Camellia",
                          "Encrypt selected region with ChaCha20",
                          "Encrypt selected region with DES",
                          "Encrypt selected region with RC2",
                          "Encrypt selected region with RC4",
                          "Encrypt selected region with RC5",
                          "Encrypt selected region with RC6",
                          "Encrypt selected region with Salsa20",
                          "Encrypt selected region with TEA\n(Tiny Encryption Algorithm)",
                          "Encrypt selected region with Triple DES",
                          "Encrypt selected region with XTEA\n(eXtended Tiny Encryption Algorithm)",
                          "Encrypt selected region with XXTEA\n(Corrected Block Tiny Encryption Algorithm)")

ops_dict["Decode"] = ("Hex text to binary data",
                      "Decimal text to binary data",
                      "Octal text to binary data",
                      "Binary text to binary data",
                      "Custom base16 decode",
                      "Custom base32 decode",
                      "Custom base58 decode",
                      "Custom base62 decode",
                      "Custom base64 decode",
                      "Custom base85 decode",
                      "Custom base91 decode",
                      "MessagePack decode",
                      "Protobuf decode",
                      "From quoted printable",
                      "Unicode unescape",
                      "URL decode")
tooltip_dict["Decode"] = ("Convert hex text of selected region into binary data",
                          "Convert decimal text of selected region into binary data",
                          "Convert octal text of selected region into binary data",
                          "Convert binary text of selected region into binary data",
                          "Decode selected region with custom base16 table",
                          "Decode selected region with custom base32 table",
                          "Decode selected region with custom base58 table",
                          "Decode selected region with custom base62 table",
                          "Decode selected region with custom base64 table",
                          "Decode selected region with custom base85 table",
                          "Decode selected region with custom base91 table",
                          "Decode selected region as MessagePack serialized data",
                          "Decode selected region as Protocol Buffers serialized data without .proto files",
                          "Decode selected region as quoted printable text",
                          "Unescape Unicode escape sequence of selected region",
                          "Decode selected region as percent-encoded text\nthat is used by URL")

ops_dict["Encode"] = ("Binary data to hex text",
                      "Binary data to decimal text",
                      "Binary data to octal text",
                      "Binary data to binary text",
                      "Custom base16 encode",
                      "Custom base32 encode",
                      "Custom base58 encode",
                      "Custom base62 encode",
                      "Custom base64 encode",
                      "Custom base85 encode",
                      "Custom base91 encode",
                      "MessagePack encode",
                      "ROT13",
                      "To quoted printable",
                      "Unicode escape",
                      "URL encode")
tooltip_dict["Encode"] = ("Convert binary data of selected region into hex text",
                          "Convert binary data of selected region into decimal text",
                          "Convert binary data of selected region into octal text",
                          "Convert binary data of selected region into binary text",
                          "Encode selected region with custom base16 table",
                          "Encode selected region with custom base32 table",
                          "Encode selected region with custom base58 table",
                          "Encode selected region with custom base62 table",
                          "Encode selected region with custom base64 table",
                          "Encode selected region with custom base85 table",
                          "Encode selected region with custom base91 table",
                          "Encode JSON of selected region into MessagePack serialized data",
                          "Rotate alphabet characters in selected region by the\nspecified amount (default: 13)",
                          "Encode selected region into quoted printable text",
                          "Escape Unicode characters of selected region",
                          "Encode selected region into percent-encoded text\nthat is used by URL")

ops_dict["Misc"] = ("Emulate code",
                    "File comparison",
                    "Hash values",
                    "Send to (CLI)",
                    "Send to (GUI)")
tooltip_dict["Misc"] = ("Emulate selected region as an executable or shellcode\n(the whole file if not selected)",
                        "Compare contents of two files",
                        "Calculate hash values of CRC32, MD5, SHA1, SHA256, ssdeep, TLSH, imphash, impfuzzy, exphash,\nRich PE header hash, authentihash, icon MD5, icon dhash, and telfhash of selected region\n(the whole file if not selected)",
                        "Send selected region (the whole file if not selected) to other CLI program and show output",
                        "Send selected region (the whole file if not selected) to other GUI program")

ops_dict["Parsing"] = ("Binwalk scan",
                       "Disassemble",
                       "Extract VBA macro",
                       "File type",
                       "Find PE file",
                       "Parse file structure",
                       "Show metadata",
                       "Strings",
                       "String type")
tooltip_dict["Parsing"] = ("Scan selected region (the whole file if not selected)\nto find embedded files",
                           "Disassemble selected region\n(the whole file if not selected)",
                           "Extract Microsoft Office VBA macro from selected region\n(the whole file if not selected)",
                           "Identify file type of selected region\n(the whole file if not selected)",
                           "Find PE file from selected region\n(the whole file if not selected)\nbased on PE header information",
                           "Parse file structure of selected region\n(the whole file if not selected) with Kaitai Struct",
                           "Show metadata of selected region\n(the whole file if not selected) with ExifTool",
                           "Extract text strings from selected region\n(the whole file if not selected)",
                           "Identify type of strings such as API keys and\ncryptocurrency wallet addresses in the selected region\n(the whole file if not selected) with lemmeknow")

ops_dict["Search"] = ("Regex extraction",
                      "Regex search",
                      "Replace",
                      "XOR hex search",
                      "XOR text search",
                      "YARA scan")
tooltip_dict["Search"] = ("Search with regular expression in selected region (the whole file if not selected)\nand extract matched regions as single concatenated region",
                          "Search with regular expression in selected region\n(the whole file if not selected) and bookmark matched regions",
                          "Search with regular expression in selected region (the whole file if not selected)\nand replace matched regions with specified data",
                          "Search XORed / bit-rotated data in selected region\n(the whole file if not selected)",
                          "Search XORed / bit-rotated string in selected region\n(the whole file if not selected)",
                          "Scan selected region (the whole file if not selected)\nwith YARA.")

ops_dict["Visualization"] = ("Bitmap view",
                             "Byte histogram",
                             "Entropy graph")
tooltip_dict["Visualization"] = ("Visualize the whole file as a bitmap representation",
                                 "Show byte histogram of selected region\n(the whole file if not selected)",
                                 "Show entropy graph of selected region\n(the whole file if not selected)")

ops_dict["XOR"] = ("Simple XOR",
                   "Decremental XOR",
                   "Incremental XOR",
                   "Null-preserving XOR",
                   "XOR with another file",
                   "XOR with next byte",
                   "XOR with next byte (reverse)",
                   "Guess multibyte XOR keys",
                   "Visual Decrypt",
                   "Visual Encrypt")
tooltip_dict["XOR"] = ("XOR selected region with specified XOR key",
                       "XOR selected region while decrementing XOR key",
                       "XOR selected region while incrementing XOR key",
                       "XOR selected region while skipping null bytes and XOR key itself",
                       "XOR selected region (the whole file if not selected)\nwith the content of another file as XOR key",
                       "XOR selected region while using next byte as XOR key",
                       'Reverse operation of "XOR with next byte" plugin',
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

version = sys.argv[3]

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
        if event.widget.index("active") != None:
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

menu.add_cascade(label="Check for update", command=lambda root=root, version=version: check_update(root, version))

menu.add_cascade(label="Version info", command=lambda root=root, version=version: show_version_dialog(root, version))

root.withdraw() # Hide root window
menu.post(x, y) # Show popup menu

root.mainloop()

sys.exit(exit_value) # index number of operation is returned as exit value
