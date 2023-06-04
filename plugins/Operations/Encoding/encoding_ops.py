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
import base91
import binascii
import quopri
import re
import string
import struct
import subprocess
import urllib

def binary_data_to_hex_text(fi):
    """
    Convert binary data of selected region into hex text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()

        converted = ""
        for i in range(0, length):
            converted += "%02x" % ord(data[i])

        newdata = orig[:offset] + converted + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Binary data to hex text")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted binary data from offset %s to %s (%s bytes) into hex text." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")
    else:
        print("Please select a region to use this plugin.")

def hex_text_to_binary_data(fi):
    """
    Convert hex text of selected region into binary data
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        string = fi.getSelection()
    else:
        print("Please select a region to use this plugin.")
        return

    hexchars = list("0123456789abcdefABCDEF")

    if length >= 2:
        data = ""
        zero_x_prefix = False # Current position is next to "0x" prefix
        contiguous = False # Previous character is hex character
        for i in range(0, len(string)):
            # Skip "0x"
            if i < len(string) - 2 and string[i] == "0" and string[i+1] in "x":
                zero_x_prefix = True
                continue

            if string[i] in hexchars:
                if zero_x_prefix == True:
                    # Append "0" for 0x0, ... 0xf
                    if (i < len(string) - 1 and string[i+1] not in hexchars) or i == len(string) - 1:
                        data += "0"
                        zero_x_prefix = False
                    # Special handling is not required when there are two hex characters
                    elif i < len(string) - 1 and string[i+1] in hexchars:
                        zero_x_prefix = False
                # Skip single hex character without "0x" prefix
                elif i < len(string) - 1 and contiguous == False and string[i+1] not in hexchars:
                    continue

                data += string[i]
                contiguous = True
            else:
                contiguous = False

        if len(data) < 2:
            return

        orig = fi.getDocument()

        converted = ""
        i = 0
        while i < len(data) - 1:
            converted += chr(int(data[i] + data[i+1], 16))
            i += 2

        newdata = orig[:offset] + converted + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Hex text to binary data")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "64", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base64 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 65:
                print("Error: base64 table must be 65 characters (including padding).")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                for i in range(0, len(data)):
                    if data[i] not in custom_table:
                        print("Error: invalid character '%s' (%s) found in data at offset %s." % (data[i], hex(ord(data[i])), hex(offset + i)))
                        return

                trans = string.maketrans(custom_table, standard_table)
                decoded = base64.b64decode(data.translate(trans))

                newdata = orig[:offset] + decoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base64 decode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base64 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base64 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "64", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base64 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 65:
                print("Error: base64 table must be 65 characters (including padding).")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                trans = string.maketrans(standard_table, custom_table)
                encoded = base64.b64encode(data).translate(trans)

                newdata = orig[:offset] + encoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base64 encode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base64 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base64 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/rot13_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

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

        tab_name = fi.get_new_document_name("Output of ROT13")
        fi.newDocument(tab_name, 1)
        fi.setDocument("".join(buf))
        fi.setBookmark(offset, length, hex(offset), "#c8ffff")

        if length == 1:
            print("Decoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

def from_quoted_printable(fi):
    """
    Decode selected region as quoted printable text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()
        orig_len = len(orig)

        decoded = quopri.decodestring(data)
        newdata = orig[:offset] + decoded + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of From quoted printable")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

        if length == 1:
            print("Decoded one byte quoted printable text from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes quoted printable text from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

def to_quoted_printable(fi):
    """
    Encode selected region into quoted printable text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()
        orig_len = len(orig)

        encoded = quopri.encodestring(data)
        newdata = orig[:offset] + encoded + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of To quoted printable")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

        if length == 1:
            print("Encoded one byte into quoted printable text from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Encoded %s bytes into quoted printable text from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

def binary_data_to_binary_text(fi):
    """
    Convert binary data of selected region into binary text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()

        converted = ""
        for i in range(0, length):
            converted += "{0:b}".format(ord(data[i])).zfill(8)

        newdata = orig[:offset] + converted + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Binary data to binary text")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted binary from offset %s to %s (%s bytes) into binary text." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")
    else:
        print("Please select a region to use this plugin.")

def binary_text_to_binary_data(fi):
    """
    Convert binary text of selected region into binary data
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        string = fi.getSelection()

    binchars = list("01")

    if length >= 8:
        data = ""
        for i in range(0, len(string)):
            if string[i] in binchars:
                data += string[i]

        if len(data) < 8:
            return

        orig = fi.getDocument()

        converted = ""
        i = 0
        while i < len(data) - 7:
            converted += chr(int(data[i:i+8], 2))
            i += 8

        newdata = orig[:offset] + converted + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Binary text to binary data")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted binary text from offset %s to %s (%s bytes) into binary data." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")
    else:
        print("Please select a region at least 8 bytes to use this plugin.")

def binary_data_to_decimal_text(fi):
    """
    Convert binary data of selected region into decimal text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute delimiter_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/delimiter_dialog.py", "-s"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get delimiter setting
        stdout_data, stderr_data = p.communicate()
        setting = stdout_data.rstrip()

        if setting == "":
            return
        else:
            (d, endianness, single_int) = setting.split()

        delimiters = {"Space": " ",
                      "Comma": ",",
                      "Semi-colon": ";",
                      "Colon": ":",
                      "Tab": "\t",
                      "LF": "\x0a",
                      "CRLF": "\x0d\x0a"}

        converted = ""
        trail = ""
        if single_int == "True":
            data = list(data)
            if endianness == "Big":
                for i in range(0, length):
                    if i > 0:
                        converted += delimiters[d]

                    if data[i] == b"\x00":
                        converted += "0"
                    else:
                        break

                if i < length - 1:
                    data = data[i:]
                    all_zero = False
                else:
                    all_zero = True
            else:
                for i in range(length - 1, -1, -1):
                    if data[i] == b"\x00":
                        trail += delimiters[d] + "0"
                    else:
                        break

                if i > 0:
                    data = data[:i + 1]
                    data.reverse()
                    all_zero = False
                else:
                    trail = trail[1:] # Remove first delimiter
                    all_zero = True

            if all_zero:
                converted += trail
            else:
                h = binascii.b2a_hex("".join(data))
                converted += str(int(h, 16)) + trail
        else:
            for i in range(0, length):
                if i > 0:
                    converted += delimiters[d]
                converted += str(ord(data[i]))

        newdata = orig[:offset] + converted + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Binary data to decimal text")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted binary from offset %s to %s (%s bytes) into decimal text." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/delimiter_dialog.py", "-e"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get delimiter setting
        stdout_data, stderr_data = p.communicate()
        setting = stdout_data.rstrip()

        if setting == "":
            return
        else:
            (d, endianness, single_int) = setting.split()

        delimiters = {"Space": " ",
                      "Comma": ",",
                      "Semi-colon": ";",
                      "Colon": ":",
                      "Tab": "\t",
                      "LF": "\x0a",
                      "CRLF": "\x0d\x0a"}

        if d != "Space":
            data = data.replace(" ", "")

        values = re.split(delimiters[d], data, flags=re.MULTILINE | re.DOTALL)

        # Check of splitted data
        for i in range(0, len(values)):
            if values[i] == "":
                print("The selected region contains empty values (extra delimiters).")
                return
            if re.search("[^-0-9]", values[i]):
                print("The selected region contains non-numeric or non-delimiter characters.")
                return

        orig = fi.getDocument()

        converted = ""
        for i in range(0, len(values)):
            v = int(values[i])

            if v < 0:
                if v >= -128:
                    b = struct.pack("b", v)
                elif v >= -32768:
                    b = struct.pack("h", v)
                elif v >= -2147483648:
                    b = struct.pack("l", v)
                elif v >= -9223372036854775808:
                    b = struct.pack("q", v)
                else:
                    print("Error: the value %d is out of range for 64 bit integer." % v)
                    return
            else:
                h = "%x" % v
                if len(h) % 2 == 1:
                    h = "0" + h

                b = binascii.a2b_hex(h)
            if endianness == "Little":
                b = list(b)
                b.reverse()
                converted += "".join(b)
            else:
                converted += b

        newdata = orig[:offset] + converted + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Decimal text to binary data")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted decimal text from offset %s to %s (%s bytes) into binary data." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")
    else:
        print("Please select a region to use this plugin.")

def binary_data_to_octal_text(fi):
    """
    Convert binary data of selected region into octal text
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute delimiter_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/delimiter_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get delimiter setting
        stdout_data, stderr_data = p.communicate()
        setting = stdout_data.rstrip()

        if setting == "":
            return
        else:
            (d, endianness, single_int) = setting.split()

        delimiters = {"Space": " ",
                      "Comma": ",",
                      "Semi-colon": ";",
                      "Colon": ":",
                      "Tab": "\t",
                      "LF": "\x0a",
                      "CRLF": "\x0d\x0a"}

        orig = fi.getDocument()

        converted = ""
        for i in range(0, length):
            if i > 0:
                converted += delimiters[d]
            converted += oct(ord(data[i]))

        newdata = orig[:offset] + converted + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Binary data to octal text")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted binary from offset %s to %s (%s bytes) into octal text." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/delimiter_dialog.py"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get delimiter setting
        stdout_data, stderr_data = p.communicate()
        setting = stdout_data.rstrip()

        if setting == "":
            return
        else:
            (d, endianness, single_int) = setting.split()

        delimiters = {"Space": " ",
                      "Comma": ",",
                      "Semi-colon": ";",
                      "Colon": ":",
                      "Tab": "\t",
                      "LF": "\x0a",
                      "CRLF": "\x0d\x0a"}

        values = re.split(delimiters[d], data, flags=re.MULTILINE | re.DOTALL)

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

        orig = fi.getDocument()

        converted = ""
        for i in range(0, len(values)):
            converted += chr(int(values[i], 8))

        newdata = orig[:offset] + converted + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Octal text to binary data")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(converted), hex(offset), "#c8ffff")

        print("Converted octal text from offset %s to %s (%s bytes) into binary data." % (hex(offset), hex(offset + length - 1), length))
        print("Added a bookmark to converted region.")
    else:
        print("Please select a region to use this plugin.")

def url_decode(fi):
    """
    Decode selected region as percent-encoded text that is used by URL
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()
        orig_len = len(orig)

        decoded = urllib.unquote(data)
        newdata = orig[:offset] + decoded + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of URL decode")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

        if length == 1:
            print("Decoded one byte URL encoded text from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes URL encoded text from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

def url_encode(fi):
    """
    Encode selected region into percent-encoded text that is used by URL
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()
        orig_len = len(orig)

        encoded = urllib.quote(data)

        newdata = orig[:offset] + encoded + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of URL encode")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

        if length == 1:
            print("Encoded one byte into URL encoded text from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Encoded %s bytes into URL encoded text from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/unicode_format_dialog.py", "-e"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get format setting
        stdout_data, stderr_data = p.communicate()
        if stdout_data == "":
            return

        escape_format, encoding = stdout_data.split()

        data = fi.getSelection()
        orig = fi.getDocument()
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
                for c in escaped_orig:
                    if escape_format == "%u":
                        escaped += c.encode("raw-unicode-escape").replace("\\u", "%u")
                    else:
                        escaped += c.encode("raw-unicode-escape")

        except Exception as e:
            print("Escape failed.")
            print("Error: %s" % e)
            return

        newdata = orig[:offset] + escaped + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Unicode escape")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(escaped), hex(offset), "#c8ffff")

        if length == 1:
            print("Escaped one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Escaped %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to escaped region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/unicode_format_dialog.py", "-u"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get format setting
        stdout_data, stderr_data = p.communicate()
        if stdout_data == "":
            return

        escape_format, encoding = stdout_data.split()

        data = fi.getSelection()
        orig = fi.getDocument()
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

        newdata = orig[:offset] + unescaped + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of Unicode unescape")
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, len(unescaped), hex(offset), "#c8ffff")

        if length == 1:
            print("Unescaped one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Unescaped %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to unescaped region.")
    else:
        print("Please select a region to use this plugin.")

def protobuf_decode(fi):
    """
    Decode selected region as Protocol Buffers serialized data into JSON without .proto files
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute protobuf_decode.py to decode data
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/protobuf_decode.py", "-u"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Receive decoded data
        stdout_data, stderr_data = p.communicate(data)
        ret = p.wait()

        if ret == -1: # blackboxprotobuf (forked version) is not installed
            fi.show_module_install_instruction("blackboxprotobuf (forked version)", "blackboxprotobuf")
            return
        elif ret == 1:
            print("Error: decode failed.")
            print(stderr_data)
            return

        tab_name = fi.get_new_document_name("Output of Protobuf decode")
        fi.newDocument(tab_name)
        fi.setDocument(stdout_data)

        if length == 1:
            print("Decoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
    else:
        print("Please select a region to use this plugin.")

def custom_base16_decode(fi):
    """
    Decode selected region with custom base16 table
    """
    standard_table = "0123456789ABCDEF"

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "16", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base16 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 16:
                print("Error: base16 table must be 16 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                for i in range(0, len(data)):
                    if data[i] not in custom_table:
                        print("Error: invalid character '%s' (%s) found in data at offset %s." % (data[i], hex(ord(data[i])), hex(offset + i)))
                        return

                trans = string.maketrans(custom_table, standard_table)
                decoded = base64.b16decode(data.translate(trans))

                newdata = orig[:offset] + decoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base16 decode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base16 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base16 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

def custom_base16_encode(fi):
    """
    Encode selected region with custom base16 table
    """
    standard_table = "0123456789ABCDEF"

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "16", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base16 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 16:
                print("Error: base16 table must be 16 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                trans = string.maketrans(standard_table, custom_table)
                encoded = base64.b16encode(data).translate(trans)

                newdata = orig[:offset] + encoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base16 encode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base16 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base16 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "32", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base32 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 33:
                print("Error: base32 table must be 33 characters (including padding).")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                for i in range(0, len(data)):
                    if data[i] not in custom_table:
                        print("Error: invalid character '%s' (%s) found in data at offset %s." % (data[i], hex(ord(data[i])), hex(offset + i)))
                        return

                trans = string.maketrans(custom_table, standard_table)
                decoded = base64.b32decode(data.translate(trans))

                newdata = orig[:offset] + decoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base32 decode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base32 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base32 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "32", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base32 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 33:
                print("Error: base32 table must be 33 characters (including padding).")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                trans = string.maketrans(standard_table, custom_table)
                encoded = base64.b32encode(data).translate(trans)

                newdata = orig[:offset] + encoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base32 encode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base32 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base32 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "58", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base58 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 58:
                print("Error: base58 table must be 58 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                for i in range(0, len(data)):
                    if data[i] not in custom_table:
                        print("Error: invalid character '%s' (%s) found in data at offset %s." % (data[i], hex(ord(data[i])), hex(offset + i)))
                        return

                # Execute base58_decode.py to decode data
                p = subprocess.Popen([fi.get_embed_python(), "Encoding/base58_decode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Receive decoded data
                trans = string.maketrans(custom_table, standard_table)
                stdout_data, stderr_data = p.communicate(data.translate(trans))
                ret = p.wait()

                if ret == -1: # base58 is not installed
                    fi.show_module_install_instruction("base58")
                    return
                elif ret == 1:
                    print("Error: decode failed.")
                    print(stderr_data)
                    return

                decoded = stdout_data
                newdata = orig[:offset] + decoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base58 decode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base58 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base58 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

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
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "58", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base58 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 58:
                print("Error: base58 table must be 58 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                # Execute base58_encode.py to encode data
                p = subprocess.Popen([fi.get_embed_python(), "Encoding/base58_encode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Receive encoded data
                stdout_data, stderr_data = p.communicate(data)
                ret = p.wait()

                if ret == -1: # base58 is not installed
                    fi.show_module_install_instruction("base58")
                    return
                elif ret == 1:
                    print("Error: encode failed.")
                    print(stderr_data)
                    return

                trans = string.maketrans(standard_table, custom_table)
                encoded = stdout_data.translate(trans)

                newdata = orig[:offset] + encoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base58 encode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base58 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base58 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

def custom_base85_decode(fi):
    """
    Decode selected region with custom base85 table
    """
    standard_table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "85", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base85 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 85:
                print("Error: base85 table must be 85 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                for i in range(0, len(data)):
                    if data[i] not in custom_table:
                        print("Error: invalid character '%s' (%s) found in data at offset %s." % (data[i], hex(ord(data[i])), hex(offset + i)))
                        return

                # Execute base85_decode.py to decode data
                p = subprocess.Popen([fi.get_embed_python(), "Encoding/base85_decode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Receive decoded data
                trans = string.maketrans(custom_table, standard_table)
                stdout_data, stderr_data = p.communicate(data.translate(trans))
                ret = p.wait()

                if ret == 1:
                    print("Error: decode failed.")
                    print(stderr_data)
                    return

                decoded = stdout_data
                newdata = orig[:offset] + decoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base85 decode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base85 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base85 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

def custom_base85_encode(fi):
    """
    Encode selected region with custom base85 table
    """
    standard_table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "85", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base85 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 85:
                print("Error: base85 table must be 85 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                # Execute base85_encode.py to encode data
                p = subprocess.Popen([fi.get_embed_python(), "Encoding/base85_encode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Receive encoded data
                stdout_data, stderr_data = p.communicate(data)
                ret = p.wait()

                if ret == 1:
                    print("Error: encode failed.")
                    print(stderr_data)
                    return

                trans = string.maketrans(standard_table, custom_table)
                encoded = stdout_data.translate(trans)

                newdata = orig[:offset] + encoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base85 encode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base85 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base85 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

def custom_base62_decode(fi):
    """
    Decode selected region with custom base62 table
    """
    standard_table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "62", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base62 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 62:
                print("Error: base62 table must be 62 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                for i in range(0, len(data)):
                    if data[i] not in custom_table:
                        print("Error: invalid character '%s' (%s) found in data at offset %s." % (data[i], hex(ord(data[i])), hex(offset + i)))
                        return

                # Execute base62_decode.py to decode data
                p = subprocess.Popen([fi.get_embed_python(), "Encoding/base62_decode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Receive decoded data
                trans = string.maketrans(custom_table, standard_table)
                stdout_data, stderr_data = p.communicate(data.translate(trans))
                ret = p.wait()

                if ret == -1: # pybase62 is not installed
                    fi.show_module_install_instruction("base62", "pybase62")
                    return
                elif ret == 1:
                    print("Error: decode failed.")
                    print(stderr_data)
                    return

                decoded = stdout_data
                newdata = orig[:offset] + decoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base62 decode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base62 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base62 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

def custom_base62_encode(fi):
    """
    Encode selected region with custom base62 table
    """
    standard_table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "62", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base62 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 62:
                print("Error: base62 table must be 62 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                # Execute base62_encode.py to encode data
                p = subprocess.Popen([fi.get_embed_python(), "Encoding/base62_encode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Receive encoded data
                stdout_data, stderr_data = p.communicate(data)
                ret = p.wait()

                if ret == -1: # pybase62 is not installed
                    fi.show_module_install_instruction("base62", "pybase62")
                    return
                elif ret == 1:
                    print("Error: encode failed.")
                    print(stderr_data)
                    return

                trans = string.maketrans(standard_table, custom_table)
                encoded = stdout_data.translate(trans)

                newdata = orig[:offset] + encoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base62 encode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base62 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base62 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

def messagepack_decode(fi):
    """
    Decode selected region as MessagePack serialized data into JSON
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute messagepack_decode.py to decode data
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/messagepack_decode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Receive decoded data
        stdout_data, stderr_data = p.communicate(data)
        ret = p.wait()

        if ret == -1: # msgpack is not installed
            fi.show_module_install_instruction("msgpack", "msgpack")
            return
        elif ret == 1:
            print("Error: decode failed.")
            print(stderr_data)
            return

        tab_name = fi.get_new_document_name("Output of MessagePack decode")
        fi.newDocument(tab_name)
        fi.setDocument(stdout_data)

        if length == 1:
            print("Decoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
    else:
        print("Please select a region to use this plugin.")

def messagepack_encode(fi):
    """
    Encode JSON of selected region into MessagePack serialized data
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute messagepack_encode.py to encode data
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/messagepack_encode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Receive encoded data
        stdout_data, stderr_data = p.communicate(data)
        ret = p.wait()

        if ret == -1: # msgpack is not installed
            fi.show_module_install_instruction("msgpack", "msgpack")
            return
        elif ret == 1:
            print("Error: encode failed.")
            print(stderr_data)
            return

        tab_name = fi.get_new_document_name("Output of MessagePack encode")
        fi.newDocument(tab_name, 1)
        fi.setDocument(stdout_data)

        if length == 1:
            print("Encoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Encoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
    else:
        print("Please select a region to use this plugin.")

def custom_base91_decode(fi):
    """
    Decode selected region with custom base91 table
    """
    standard_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "91", "decode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base91 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 91:
                print("Error: base91 table must be 91 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                for i in range(0, len(data)):
                    if data[i] not in custom_table:
                        print("Error: invalid character '%s' (%s) found in data at offset %s." % (data[i], hex(ord(data[i])), hex(offset + i)))
                        return

                # Receive decoded data
                trans = string.maketrans(custom_table, standard_table)
                decoded = bytes(base91.decode(data.translate(trans)))

                newdata = orig[:offset] + decoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base91 decode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(decoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Decoded one byte with custom base91 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Decoded %s bytes with custom base91 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to decoded region.")
    else:
        print("Please select a region to use this plugin.")

def custom_base91_encode(fi):
    """
    Encode selected region with custom base91 table
    """
    standard_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute custom_basexx_dialog.py to show GUI
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/custom_basexx_dialog.py", "91", "encode"], startupinfo=startupinfo, stdout=subprocess.PIPE)

        # Get base91 table input
        stdout_data, stderr_data = p.communicate()
        custom_table = stdout_data.rstrip()
        custom_table_length = len(custom_table)

        if custom_table_length > 0:
            if custom_table_length != 91:
                print("Error: base91 table must be 91 characters.")
            else:
                data = fi.getSelection()
                orig = fi.getDocument()
                orig_len = len(orig)

                trans = string.maketrans(standard_table, custom_table)
                encoded = base91.encode(data).translate(trans)

                newdata = orig[:offset] + encoded + orig[offset + length:]

                tab_name = fi.get_new_document_name("Output of Custom base91 encode")
                fi.newDocument(tab_name, 1)
                fi.setDocument(newdata)
                fi.setBookmark(offset, len(encoded), hex(offset), "#c8ffff")

                if length == 1:
                    print("Encoded one byte with custom base91 table from offset %s to %s." % (hex(offset), hex(offset)))
                else:
                    print("Encoded %s bytes with custom base91 table from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
                print("Added a bookmark to encoded region.")
    else:
        print("Please select a region to use this plugin.")

def gob_decode(fi):
    """
    Decode selected region as gob (serialization format for golang) serialized data into Python notation
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute gob_decode.py to decode data
        p = subprocess.Popen([fi.get_embed_python(), "Encoding/gob_decode.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Receive decoded data
        stdout_data, stderr_data = p.communicate(data)
        ret = p.wait()

        if ret == -1: # Goblin is not installed
            print("pygob Python module is not installed.")
            print("Please install it with the following command and try again.")
            print("&'%s' -m pip install https://github.com/Zrocket/Goblin/archive/refs/heads/master.zip" % fi.get_embed_python())
            return
        elif ret == 1:
            print("Error: decode failed.")
            print(stderr_data)
            return

        tab_name = fi.get_new_document_name("Output of gob decode")
        fi.newDocument(tab_name)
        fi.setDocument(stdout_data)

        if length == 1:
            print("Decoded one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decoded %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
    else:
        print("Please select a region to use this plugin.")
