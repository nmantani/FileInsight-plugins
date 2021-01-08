#
# Encoding operations - Various encoding operations
#
# Copyright (c) 2018, Nobutaka Mantani
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

import base64
import binascii
import quopri
import re
import string
import subprocess
import urllib

def binary_data_to_hex_text(fi):
    """
    Convert binary data of selected region into hex text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = list(fi.getSelection())
        orig = list(fi.getDocument())
        newdata = orig[:offset]

        converted = []
        for i in range(0, length):
            converted.append("%02x" % ord(data[i]))

        newdata.extend(converted)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Binary data to hex text", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(converted)), hex(offset), "#c8ffff")

        print("Converted binary data from offset %s to %s (%s bytes) into hex text." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")

def hex_text_to_binary_data(fi):
    """
    Convert hex text of selected region into binary data
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        string = list(fi.getSelection())
    else:
        return

    hexchars = list("0123456789abcdefABCDEF")

    if length >= 2:
        data = []
        for i in range(0, len(string)):
            # skip "0x"
            if i < len(string) - 2 and string[i] == "0" and string[i+1] in "x":
                continue

            if string[i] in hexchars:
                data.append(string[i])

        if len(data) < 2:
            return

        orig = list(fi.getDocument())
        newdata = orig[:offset]

        converted = []
        i = 0
        while i < len(data) - 1:
            converted.append(chr(int(data[i] + data[i+1], 16)))
            i += 2

        newdata.extend(converted)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Hex text to binary data", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted hex text from offset %s to %s (%s bytes) into binary data (non-hex characters are skipped)." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")

def custom_base64_decode(fi):
    """
    Decode selected region with custom base64 table
    """
    standard_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "Encoding/custom_basexx_dialog.py", "64", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base64 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 65:
                print("Error: base64 table must be 65 characters (including padding).")
            else:
                data = fi.getSelection()
                orig = list(fi.getDocument())
                orig_len = len(orig)

                trans = string.maketrans(custom_table, standard_table)
                encoded = list(base64.b64decode(data.translate(trans)))

                newdata = orig[:offset]
                newdata.extend(encoded)
                newdata.extend(orig[offset + length:])

                fi.newDocument("Output of Custom base64 decode", 1)
                fi.setDocument("".join(newdata))
                fi.setBookmark(offset, len("".join(encoded)), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base64 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base64 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")

def custom_base64_encode(fi):
    """
    Encode selected region with custom base64 table
    """
    standard_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "Encoding/custom_basexx_dialog.py", "64", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base64 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 65:
                print("Error: base64 table must be 65 characters (including padding).")
            else:
                data = fi.getSelection()
                orig = list(fi.getDocument())
                orig_len = len(orig)

                trans = string.maketrans(standard_table, custom_table)
                encoded = list(base64.b64encode(data).translate(trans))

                newdata = orig[:offset]
                newdata.extend(encoded)
                newdata.extend(orig[offset + length:])

                fi.newDocument("Output of Custom base64 encode", 1)
                fi.setDocument("".join(newdata))
                fi.setBookmark(offset, len("".join(encoded)), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base64 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base64 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")

def rot13(fi):
    """
    Rotate alphabet characters in selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        buf = list(fi.getDocument())
        data = fi.getSelection()

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute rot13_dialog.py to show GUI
        # GUI portion is moved to rot13_dialog.py to avoid hangup of FileInsight
        p = subprocess.Popen(["py.exe", "-3", "Encoding/rot13_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get amount input
        stdout_data, stderr_data = p.communicate()
        amount = stdout_data.rstrip()
        if len(amount) > 0:
            amount = int(amount)

            if amount < 0:
                amount = 26 - (abs(amount) % 26)
            elif amount == 0:
                return
            else:
                amount = amount % 26
        else:
            return

        # Create a dictionary for rotation
        d = {}
        for c in (0x41, 0x61): # "A" and "a"
            for i in range(26):
                d[chr(i + c)] = chr((i + amount) % 26 + c)

        for i in range(0, length):
            buf[offset + i] = d.get(data[i], data[i])

        fi.newDocument("Output of ROT13", 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Decoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decoded region.")

def from_quoted_printable(fi):
    """
    Decode selected region as quoted printable text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        decoded = list(quopri.decodestring(data))

        newdata = orig[:offset]
        newdata.extend(decoded)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of From quoted printable", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(decoded)), hex(offset), "#c8ffff")

        if length == 1:
            print("Decoded one byte quoted printable text from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes quoted printable text from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decoded region.")

def to_quoted_printable(fi):
    """
    Encode selected region into quoted printable text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        encoded = list(quopri.encodestring(data))

        newdata = orig[:offset]
        newdata.extend(encoded)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of To quoted printable", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(encoded)), hex(offset), "#c8ffff")

        if length == 1:
            print("Encoded one byte into quoted printable text from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Encoded %s bytes into quoted printable text from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to encoded region.")

def binary_data_to_binary_text(fi):
    """
    Convert binary data of selected region into binary text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = list(fi.getSelection())
        orig = list(fi.getDocument())
        newdata = orig[:offset]

        converted = []
        for i in range(0, length):
            converted.append("{0:b}".format(ord(data[i])).zfill(8))

        newdata.extend(converted)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Binary data to binary text", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(converted)), hex(offset), "#c8ffff")

        print("Converted binary from offset %s to %s (%s bytes) into binary text." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")

def binary_text_to_binary_data(fi):
    """
    Convert binary text of selected region into binary data
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    string = list(fi.getSelection())

    binchars = list("01")

    if length >= 8:
        data = []
        for i in range(0, len(string)):
            if string[i] in binchars:
                data.append(string[i])

        if len(data) < 8:
            return

        orig = list(fi.getDocument())
        newdata = orig[:offset]

        converted = []
        i = 0
        while i < len(data) - 7:
            converted.append(chr(int("".join(data[i:i+8]), 2)))
            i += 8

        newdata.extend(converted)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Binary text to binary data", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted binary text from offset %s to %s (%s bytes) into binary data." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")

def binary_data_to_decimal_text(fi):
    """
    Convert binary data of selected region into decimal text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = list(fi.getSelection())
        orig = list(fi.getDocument())
        newdata = orig[:offset]

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute delimiter_dialog.py to show GUI
        # GUI portion is moved to decimal_dialog.py to avoid hangup of FileInsight
        p = subprocess.Popen(["py.exe", "-3", "Encoding/delimiter_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get delimiter setting
        stdout_data, stderr_data = p.communicate()
        setting = stdout_data.rstrip()

        if setting == "":
            return

        delimiters = {"Space": " ",
                      "Comma": ",",
                      "Semi-colon": ";",
                      "Colon": ":",
                      "Tab": "\t",
                      "LF": "\x0a",
                      "CRLF": "\x0d\x0a"}

        converted = []
        for i in range(0, length):
            if i > 0:
                converted.append(delimiters[setting])
            converted.append(str(ord(data[i])))

        newdata.extend(converted)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Binary data to decimal text", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(converted)), hex(offset), "#c8ffff")

        print("Converted binary from offset %s to %s (%s bytes) into decimal text." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")

def decimal_text_to_binary_data(fi):
    """
    Convert decimal text of selected region into binary data
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    data = fi.getSelection()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute delimiter_dialog.py to show GUI
        # GUI portion is moved to decimal_dialog.py to avoid hangup of FileInsight
        p = subprocess.Popen(["py.exe", "-3", "Encoding/delimiter_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get delimiter setting
        stdout_data, stderr_data = p.communicate()
        setting = stdout_data.rstrip()

        if setting == "":
            return

        delimiters = {"Space": " ",
                      "Comma": ",",
                      "Semi-colon": ";",
                      "Colon": ":",
                      "Tab": "\t",
                      "LF": "\x0a",
                      "CRLF": "\x0d\x0a"}

        pattern = "([0-9]{1,3}),"
        values = re.split(delimiters[setting], data, flags=re.MULTILINE | re.DOTALL)

        # Check of splitted data
        for i in range(0, len(values)):
            if values[i] == "":
                print("The selected region contains empty values (extra delimiters).")
                return
            if re.search("[^0-9]", values[i]):
                print("The selected region contains non-numeric or non-delimiter characters.")
                return
            if int(values[i]) < 0 or int(values[i]) > 255:
                print("The selected region contains values out of range (0-255).")
                return

        orig = list(fi.getDocument())
        newdata = orig[:offset]

        converted = []
        for i in range(0, len(values)):
            converted.append(chr(int(values[i])))

        newdata.extend(converted)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Decimal text to binary data", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(converted)), hex(offset), "#c8ffff")

        print("Converted decimal text from offset %s to %s (%s bytes) into binary data." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")

def binary_data_to_octal_text(fi):
    """
    Convert binary data of selected region into octal text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = list(fi.getSelection())
        orig = list(fi.getDocument())
        newdata = orig[:offset]

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute delimiter_dialog.py to show GUI
        # GUI portion is moved to decimal_dialog.py to avoid hangup of FileInsight
        p = subprocess.Popen(["py.exe", "-3", "Encoding/delimiter_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get delimiter setting
        stdout_data, stderr_data = p.communicate()
        setting = stdout_data.rstrip()

        if setting == "":
            return

        delimiters = {"Space": " ",
                      "Comma": ",",
                      "Semi-colon": ";",
                      "Colon": ":",
                      "Tab": "\t",
                      "LF": "\x0a",
                      "CRLF": "\x0d\x0a"}

        orig = list(fi.getDocument())
        newdata = orig[:offset]

        converted = []
        for i in range(0, length):
            if i > 0:
                converted.append(delimiters[setting])
            converted.append(oct(ord(data[i])))

        newdata.extend(converted)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Binary data to octal text", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(converted)), hex(offset), "#c8ffff")

        print("Converted binary from offset %s to %s (%s bytes) into octal text." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")

def octal_text_to_binary_data(fi):
    """
    Convert octal text of selected region into binary data
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()
    data = fi.getSelection()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute delimiter_dialog.py to show GUI
        # GUI portion is moved to decimal_dialog.py to avoid hangup of FileInsight
        p = subprocess.Popen(["py.exe", "-3", "Encoding/delimiter_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get delimiter setting
        stdout_data, stderr_data = p.communicate()
        setting = stdout_data.rstrip()

        if setting == "":
            return

        delimiters = {"Space": " ",
                      "Comma": ",",
                      "Semi-colon": ";",
                      "Colon": ":",
                      "Tab": "\t",
                      "LF": "\x0a",
                      "CRLF": "\x0d\x0a"}

        pattern = "([0-9]{1,3}),"
        values = re.split(delimiters[setting], data, flags=re.MULTILINE | re.DOTALL)

        # Check of splitted data
        for i in range(0, len(values)):
            if values[i] == "":
                print("The selected region contains empty values (extra delimiters).")
                return
            if re.search("[^0-9]", values[i]):
                print("The selected region contains non-numeric or non-delimiter characters.")
                return
            if int(values[i], 8) < 0 or int(values[i], 8) > 255:
                print("The selected region contains values out of range (0-255).")
                return

        orig = list(fi.getDocument())
        newdata = orig[:offset]

        converted = []
        for i in range(0, len(values)):
            converted.append(chr(int(values[i], 8)))

        newdata.extend(converted)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Octal text to binary data", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(converted)), hex(offset), "#c8ffff")

        print("Converted octal text from offset %s to %s (%s bytes) into binary data." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")

def url_decode(fi):
    """
    Decode selected region as percent-encoded text that is used by URL
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        decoded = list(urllib.unquote(data))

        newdata = orig[:offset]
        newdata.extend(decoded)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of URL decode", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(decoded)), hex(offset), "#c8ffff")

        if length == 1:
            print("Decoded one byte URL encoded text from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes URL encoded text from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decoded region.")

def url_encode(fi):
    """
    Encode selected region into percent-encoded text that is used by URL
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        encoded = list(urllib.quote(data))

        newdata = orig[:offset]
        newdata.extend(encoded)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of URL encode", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(encoded)), hex(offset), "#c8ffff")

        if length == 1:
            print("Encoded one byte into URL encoded text from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Encoded %s bytes into URL encoded text from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to encoded region.")

def unicode_escape(fi):
    """
    Escape Unicode characters of selected region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute unicode_format_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "Encoding/unicode_format_dialog.py", "-e"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get format setting
        stdout_data, stderr_data = p.communicate()
        if stdout_data == "":
            return

        escape_format, encoding = stdout_data.split()

        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        try:
            escaped_orig = data.decode(encoding)

            if escape_format == "\\U":
                escaped = escaped_orig.encode("raw-unicode-escape")
            elif escape_format in ["\\u{", "`u", "U+"]:
                escaped = escaped_orig.encode("raw-unicode-escape")

                if escape_format == "\\u{":
                    escaped = re.sub("\\\\U([0-9a-f]{8})", "\\u{\\1}", escaped)
                    escaped = re.sub("\\\\u([0-9a-f]{4})", "\\u{\\1}", escaped)
                    escaped = re.sub("\\\\u\{0{1,}", "\\u{", escaped) # remove continuous zeros
                elif escape_format == "`u":
                    escaped = re.sub("\\\\U([0-9a-f]{8})", "`u{\\1}", escaped)
                    escaped = re.sub("\\\\u([0-9a-f]{4})", "`u{\\1}", escaped)
                    escaped = re.sub("`u\{0{1,}", "`u{", escaped) # remove continuous zeros
                elif escape_format == "U+":
                    escaped = re.sub("\\\\U([0-9a-f]{8})", "U+\\1", escaped)
                    escaped = re.sub("\\\\u([0-9a-f]{4})", "U+\\1", escaped)
                    escaped = re.sub("U\+0{1,}", "U+", escaped) # remove continuous zeros
            elif escape_format in ["\\u", "%u"]:
                escaped = ""

                # convert \Uxxxxxxxx to \uxxxx + \uxxxx surrogate pair (such as emojis)
                for c in list(escaped_orig):
                    if escape_format == "%u":
                        escaped += c.encode("raw-unicode-escape").replace("\\u", "%u")
                    else:
                        escaped += c.encode("raw-unicode-escape")

        except Exception as e:
            print("Escape failed.")
            print("Error: %s" % e)
            return

        newdata = orig[:offset]
        newdata.extend(escaped)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Unicode escape", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(escaped)), hex(offset), "#c8ffff")

        if length == 1:
            print("Escaped one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Escaped %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to escaped region.")

def convert_to_python_escape(pattern, data):
    """
    Convert from other Unicode escape format to Python Unicode escape format
    Used by unicode_unescape()
    """
    match = re.findall(pattern, data)
    if match:
        for m in match:
            value = re.findall("[0-9A-Fa-f]{1,6}", m)[0]
            if len(value) < 5:
                replacement = "\\u" + "0" * (4 - len(value)) + value
                data = data.replace(m, replacement)
            else:
                # Truncate value string if it is out of range of Unicode code point
                # For cases converting strings such as "U+1f602123" (it should be "U+1f602" + "123")
                truncated = ""
                while int("0x" + value, 16) > 0x10FFFF:
                    truncated += value[-1]
                    value = value[:-1]
                replacement = "\\U" + "0" * (8 - len(value)) + value + truncated
                data = data.replace(m, replacement)

    return data

def unicode_unescape(fi):
    """
    Unescape Unicode escape sequence of selected region.
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute unicode_format_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "Encoding/unicode_format_dialog.py", "-u"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get format setting
        stdout_data, stderr_data = p.communicate()
        if stdout_data == "":
            return

        escape_format, encoding = stdout_data.split()

        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        try:
            if escape_format in ["\\U", "\\u"]:
                unescaped = data.decode("raw-unicode-escape")
            elif escape_format in ["\\u{", "`u", "U+"]:
                if escape_format == "\\u{":
                    data = convert_to_python_escape("\\\\u\{[0-9A-Fa-f]{1,6}\}", data)
                elif escape_format == "`u":
                    data = convert_to_python_escape("`u\{[0-9A-Fa-f]{1,6}\}", data)
                elif escape_format == "U+":
                    data = convert_to_python_escape("U\+[0-9A-Fa-f]{1,6}", data)

                unescaped = data.decode("raw-unicode-escape")
            elif escape_format == "%u":
                data = re.sub("%u([0-9a-f]{4})", "\\u\\1", data)
                unescaped = data.decode("raw-unicode-escape")

            unescaped = unescaped.encode(encoding)
            final_size = len(unescaped)
        except Exception as e:
            print("Unescape failed.")
            print("Error: %s" % e)
            return

        newdata = orig[:offset]
        newdata.extend(unescaped)
        newdata.extend(orig[offset + length:])

        fi.newDocument("Output of Unicode unescape", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, len("".join(unescaped)), hex(offset), "#c8ffff")

        if length == 1:
            print("Unescaped one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Unescaped %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to unescaped region.")

def protobuf_decode(fi):
    """
    Decode selected region as Protocol Buffers serialized data without .proto files
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute protobuf_decode.py to decode data
        p = subprocess.Popen(["py.exe", "-3", "Encoding/protobuf_decode.py", "-u"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Receive decoded data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        if ret == -1: # blackboxprotobuf (forked version) is not installed
            print("blackboxprotobuf (forked version) is not installed.")
            print("Please install it with 'py.exe -3 -m pip install blackboxprotobuf' and try again.")
            return

        fi.newDocument("Output of Protobuf decode")
        fi.setDocument(stdout_data)

        if length == 1:
            print("Decoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))

def custom_base32_decode(fi):
    """
    Decode selected region with custom base32 table
    """
    standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "Encoding/custom_basexx_dialog.py", "32", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base32 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 33:
                print("Error: base32 table must be 33 characters (including padding).")
            else:
                data = fi.getSelection()
                orig = list(fi.getDocument())
                orig_len = len(orig)

                trans = string.maketrans(custom_table, standard_table)
                decoded = list(base64.b32decode(data.translate(trans)))

                newdata = orig[:offset]
                newdata.extend(decoded)
                newdata.extend(orig[offset + length:])

                fi.newDocument("Output of Custom base32 decode", 1)
                fi.setDocument("".join(newdata))
                fi.setBookmark(offset, len("".join(decoded)), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base32 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base32 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")

def custom_base32_encode(fi):
    """
    Encode selected region with custom base32 table
    """
    standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "Encoding/custom_basexx_dialog.py", "32", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base32 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 33:
                print("Error: base32 table must be 33 characters (including padding).")
            else:
                data = fi.getSelection()
                orig = list(fi.getDocument())
                orig_len = len(orig)

                trans = string.maketrans(standard_table, custom_table)
                encoded = list(base64.b32encode(data).translate(trans))

                newdata = orig[:offset]
                newdata.extend(encoded)
                newdata.extend(orig[offset + length:])

                fi.newDocument("Output of Custom base32 encode", 1)
                fi.setDocument("".join(newdata))
                fi.setBookmark(offset, len("".join(encoded)), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base32 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base32 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")

def custom_base58_decode(fi):
    """
    Decode selected region with custom base58 table
    """
    standard_table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "Encoding/custom_basexx_dialog.py", "58", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base58 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 58:
                print("Error: base58 table must be 58 characters.")
            else:
                data = fi.getSelection()
                orig = list(fi.getDocument())
                orig_len = len(orig)

                # Execute base58_decode.py to encode data
                p = subprocess.Popen(["py.exe", "-3", "Encoding/base58_decode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Receive decoded data
                trans = string.maketrans(custom_table, standard_table)
                stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data.translate(trans)))
                ret = p.wait()

                if ret == -1: # base58 is not installed
                    print("base58 is not installed.")
                    print("Please install it with 'py.exe -3 -m pip install base58' and try again.")
                    return

                decoded = list(binascii.a2b_hex(stdout_data))

                newdata = orig[:offset]
                newdata.extend(decoded)
                newdata.extend(orig[offset + length:])

                fi.newDocument("Output of Custom base58 decode", 1)
                fi.setDocument("".join(newdata))
                fi.setBookmark(offset, len("".join(decoded)), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base58 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base58 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")

def custom_base58_encode(fi):
    """
    Encode selected region with custom base58 table
    """
    standard_table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen(["py.exe", "-3", "Encoding/custom_basexx_dialog.py", "58", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base58 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 58:
                print("Error: base58 table must be 58 characters.")
            else:
                data = fi.getSelection()
                orig = list(fi.getDocument())
                orig_len = len(orig)

                # Execute base58_encode.py to encode data
                p = subprocess.Popen(["py.exe", "-3", "Encoding/base58_encode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Receive encoded data
                stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
                ret = p.wait()

                if ret == -1: # base58 is not installed
                    print("base58 is not installed.")
                    print("Please install it with 'py.exe -3 -m pip install base58' and try again.")
                    return

                trans = string.maketrans(standard_table, custom_table)
                encoded = list(binascii.a2b_hex(stdout_data).translate(trans))

                newdata = orig[:offset]
                newdata.extend(encoded)
                newdata.extend(orig[offset + length:])

                fi.newDocument("Output of Custom base58 encode", 1)
                fi.setDocument("".join(newdata))
                fi.setBookmark(offset, len("".join(encoded)), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base58 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base58 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")
