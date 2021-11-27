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

import ctypes
import os
import re
import subprocess
import sys

__version__ = "2.14"

sys.path.append("./Basic")
import basic_ops

sys.path.append("./Compression")
import compression_ops

sys.path.append("./Crypto")
import crypto_ops

sys.path.append("./Encoding")
import encoding_ops

sys.path.append("./Misc")
import misc_ops

sys.path.append("./Parsing")
import parsing_ops

sys.path.append("./Search")
import search_ops

sys.path.append("./Visualization")
import visualization_ops

sys.path.append("./XOR")
import xor_ops

class FileInsight:
    """
    Class for FileInsight built-in functions
    """
    def __init__(self):
        self.getLength = getLength
        self.getByteAt = getByteAt
        self.setByteAt = setByteAt
        self.setBookmark = setBookmark
        self.getSelection = getSelection
        self.getSelectionOffset = getSelectionOffset
        self.getSelectionLength = getSelectionLength
        self.gotoBookmark = gotoBookmark
        self.download = download
        self.newDocument = newDocument
        self.decode = decode
        self.setDocument = setDocument
        self.getDocumentName = getDocumentName
        self.getDocumentCount = getDocumentCount
        self.getDocumentURL = getDocumentURL
        self.activateDocumentAt = activateDocumentAt

    # Workaround for the truncation bug of getDocument()
    def getDocument(self):
        length = getLength()

        if length == getSelectionLength():
            data = getSelection()
        else:
            data = getDocument()
            if length - len(data) > 0:
                for i in range(len(data), length):
                    data += getByteAt(i)

        return data

    # Workaround for the bug of showSimpleDialog()
    def showSimpleDialog(self, prompt):
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute show_simple_dialog.py to show GUI
        # GUI portion is moved to separate process to avoid hangup of FileInsight
        p = subprocess.Popen(["py.exe", "-3", "show_simple_dialog.py", prompt], startupinfo=startupinfo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Get input
        stdout_data, stderr_data = p.communicate()
        ret = p.wait()

        if ret: # Dialog has been closed
            return None
        else:
            return(stdout_data.rstrip())

    def get_new_document_name(self, name):
        """
        Get new document name with index number
        """
        escaped_name = re.escape(name)
        num_file = getDocumentCount()

        current_filename = getDocumentName()
        current_index = 0

        last_index = 0
        for i in range(num_file):
            activateDocumentAt(i)
            n = getDocumentName()
            m = re.match("%s (\d+)" % escaped_name, n)
            if m != None and int(m.group(1)) >= last_index:
                last_index = int(m.group(1)) + 1

            if n == current_filename:
                current_index = i

        activateDocumentAt(current_index)

        return "%s %d" % (name, last_index)

    def bookmark_yesno_dialog(self, num_bookmark):
        """
        Show a confirmation dialog of adding many bookmarks
        """
        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute bookmark_yesno_dialog.py to show confirmation dialog
        p = subprocess.Popen(["py.exe", "-3", "Misc/bookmark_yesno_dialog.py", str(num_bookmark)], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive scan result
        stdout_data, stderr_data = p.communicate()
        ret = p.wait()

        return ret

def find_python3():
    pyexe_found = False
    python3_found = False

    if os.path.exists("C:/Windows/py.exe") or os.path.exists(os.environ["LOCALAPPDATA"].replace("\\", "/") + "/Programs/Python/Launcher/py.exe"):
        pyexe_found = True

    if not pyexe_found:
        print("Error: py.exe is not found. You need to install Python 3 to use FileInsight-plugins.")
    else:
        # List Python installation
        p = subprocess.Popen(["py.exe", "--list"], startupinfo=startupinfo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Get py.exe output
        stdout_data, stderr_data = p.communicate()

        # Check whether Python 3 is installed
        if re.search("-3.[0-9]{1,2}-(64|32)", stdout_data):
            python3_found = True

    if not python3_found:
        print("Error: no Python 3 installation is found. You need to install Python 3 to use FileInsight-plugins.")

    return pyexe_found and python3_found

if __name__ == "__main__":
    # Tuple of plugin operations
    operations = (basic_ops.copy_to_new_file,
                  basic_ops.bookmark,
                  basic_ops.cut_binary_to_clipboard,
                  basic_ops.copy_binary_to_clipboard,
                  basic_ops.paste_binary_from_clipboard,
                  basic_ops.delete_before,
                  basic_ops.delete_after,
                  basic_ops.fill,
                  basic_ops.invert,
                  basic_ops.reverse_order,
                  basic_ops.change_endianness,
                  basic_ops.swap_nibbles,
                  basic_ops.swap_two_bytes,
                  basic_ops.to_upper_case,
                  basic_ops.to_lower_case,
                  basic_ops.swap_case)

    operations += (compression_ops.aplib_compress,
                   compression_ops.bzip2_compress,
                   compression_ops.gzip_compress,
                   compression_ops.lz4_compress,
                   compression_ops.lzf_compress,
                   compression_ops.lzjb_compress,
                   compression_ops.lzma_compress,
                   compression_ops.lznt1_compress,
                   compression_ops.lzo_compress,
                   compression_ops.lzrw1_kh_compress,
                   compression_ops.ppmd_compress,
                   compression_ops.quicklz_compress,
                   compression_ops.raw_deflate,
                   compression_ops.xz_compress,
                   compression_ops.zlib_compress,
                   compression_ops.zstandard_compress,
                   compression_ops.aplib_decompress,
                   compression_ops.bzip2_decompress,
                   compression_ops.gzip_decompress,
                   compression_ops.lz4_decompress,
                   compression_ops.lzf_decompress,
                   compression_ops.lzjb_decompress,
                   compression_ops.lzma_decompress,
                   compression_ops.lznt1_decompress,
                   compression_ops.lzo_decompress,
                   compression_ops.lzrw1_kh_decompress,
                   compression_ops.ppmd_decompress,
                   compression_ops.quicklz_decompress,
                   compression_ops.raw_inflate,
                   compression_ops.xz_decompress,
                   compression_ops.zlib_decompress,
                   compression_ops.zstandard_decompress)

    operations += (crypto_ops.aes_decrypt,
                   crypto_ops.arc2_decrypt,
                   crypto_ops.arc4_decrypt,
                   crypto_ops.blowfish_decrypt,
                   crypto_ops.chacha20_decrypt,
                   crypto_ops.des_decrypt,
                   crypto_ops.salsa20_decrypt,
                   crypto_ops.tea_decrypt,
                   crypto_ops.triple_des_decrypt,
                   crypto_ops.xtea_decrypt,
                   crypto_ops.aes_encrypt,
                   crypto_ops.arc2_encrypt,
                   crypto_ops.arc4_encrypt,
                   crypto_ops.blowfish_encrypt,
                   crypto_ops.chacha20_encrypt,
                   crypto_ops.des_encrypt,
                   crypto_ops.salsa20_encrypt,
                   crypto_ops.tea_encrypt,
                   crypto_ops.triple_des_encrypt,
                   crypto_ops.xtea_encrypt)

    operations += (encoding_ops.hex_text_to_binary_data,
                   encoding_ops.decimal_text_to_binary_data,
                   encoding_ops.octal_text_to_binary_data,
                   encoding_ops.binary_text_to_binary_data,
                   encoding_ops.custom_base16_decode,
                   encoding_ops.custom_base32_decode,
                   encoding_ops.custom_base58_decode,
                   encoding_ops.custom_base64_decode,
                   encoding_ops.custom_base85_decode,
                   encoding_ops.protobuf_decode,
                   encoding_ops.from_quoted_printable,
                   encoding_ops.unicode_unescape,
                   encoding_ops.url_decode,
                   encoding_ops.binary_data_to_hex_text,
                   encoding_ops.binary_data_to_decimal_text,
                   encoding_ops.binary_data_to_octal_text,
                   encoding_ops.binary_data_to_binary_text,
                   encoding_ops.custom_base16_encode,
                   encoding_ops.custom_base32_encode,
                   encoding_ops.custom_base58_encode,
                   encoding_ops.custom_base64_encode,
                   encoding_ops.custom_base85_encode,
                   encoding_ops.rot13,
                   encoding_ops.to_quoted_printable,
                   encoding_ops.unicode_escape,
                   encoding_ops.url_encode)

    operations += (misc_ops.emulate_code,
                   misc_ops.file_comparison,
                   misc_ops.hash_values,
                   misc_ops.send_to_cli,
                   misc_ops.send_to_gui)

    operations += (parsing_ops.binwalk_scan,
                   parsing_ops.disassemble,
                   parsing_ops.file_type,
                   parsing_ops.find_pe_file,
                   parsing_ops.parse_file_structure,
                   parsing_ops.show_metadata,
                   parsing_ops.strings)

    operations += (search_ops.regex_extraction,
                   search_ops.regex_search,
                   search_ops.replace,
                   search_ops.xor_hex_search,
                   search_ops.xor_text_search,
                   search_ops.yara_scan)

    operations += (visualization_ops.bitmap_view,
                   visualization_ops.byte_histogram,
                   visualization_ops.entropy_graph)

    operations += (xor_ops.decremental_xor,
                   xor_ops.incremental_xor,
                   xor_ops.null_preserving_xor,
                   xor_ops.xor_with_another_file,
                   xor_ops.xor_with_next_byte,
                   xor_ops.xor_with_next_byte_reverse,
                   xor_ops.guess_multibyte_xor_keys,
                   xor_ops.visual_decrypt,
                   xor_ops.visual_encrypt)

    # Structure for mouse cursor position
    class _point_t(ctypes.Structure):
        _fields_ = [
                    ("x",  ctypes.c_long),
                    ("y",  ctypes.c_long),
                   ]

    # Get DPI values
    DEFAULT_DPI = 96
    LOGPIXELSX = 88
    LOGPIXELSY = 90
    dc = ctypes.windll.user32.GetDC(0)
    dpi_x = ctypes.windll.gdi32.GetDeviceCaps(dc, LOGPIXELSX)
    dpi_y = ctypes.windll.gdi32.GetDeviceCaps(dc, LOGPIXELSY)
    ctypes.windll.user32.ReleaseDC(0, dc)

    # Get mouse cursor position
    point = _point_t()
    ctypes.windll.user32.GetCursorPos(ctypes.pointer(point))
    point.x = point.x * DEFAULT_DPI / dpi_x
    point.y = point.y * DEFAULT_DPI / dpi_y

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    if find_python3():
        # Execute menu.py to show GUI
        # GUI portion is moved to menu.py to avoid hangup of FileInsight
        p = subprocess.Popen(["py.exe", "-3", "menu.py", str(point.x), str(point.y), __version__], startupinfo=startupinfo)
        index = p.wait() # Receive exit value as index of selected plugin

        if index >= 0:
            fi = FileInsight()
            operations[index](fi)
        elif index == -2: # requests is not installed
            print("requests is not installed.")
            print("Please install it with 'py.exe -3 -m pip install requests' and try again.")
            print("")

    # Workaround to avoid crash of FileInsight on Windows 7
    if "threading" in sys.modules:
        sys.modules.pop("threading")
