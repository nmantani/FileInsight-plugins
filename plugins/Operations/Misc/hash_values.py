#
# Hash values - Calculate CRC32, MD5, SHA1, SHA256, ssdeep,
# TLSH, imphash, impfuzzy, exphash, Rich PE header hash,
# telfhash values of selected region (the whole file if not
# selected)
#
# Copyright (c) 2020, Nobutaka Mantani
# All rights reserved.
#
# This file is distributed under GPLv2 because it uses qiling
# Python module that is distributed under GPLv2.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import ctypes
import hashlib
import os
import pathlib
import sys
import tempfile
import zlib

try:
    import magic
except ImportError:
    sys.exit(-1) # python-magic is not installed

try:
    import pefile
except ImportError:
    sys.exit(-2) # pefile is not installed

try:
    import pyimpfuzzy
except ImportError:
    sys.exit(-3) # pyimpfuzzy-windows is not installed

try:
    import tlsh
except ImportError:
    sys.exit(-4) # py-tlsh is not installed

try:
    import telfhash
except ImportError:
    sys.exit(-5) # telfhash is not installed

def ssdeep(data):
    # Length of an individual fuzzy hash signature component
    SPAMSUM_LENGTH = 64

    # The longest possible length for a fuzzy hash signature
    FUZZY_MAX_RESULT = (2 * SPAMSUM_LENGTH + 20)

    is_64bits = sys.maxsize > 2**32
    pyimpfuzzy_path = pathlib.Path(pyimpfuzzy.__file__)

    if is_64bits:
        fuzzy_lib_path = pyimpfuzzy_path.parent / "bin" / "fuzzy64.dll"
    else:
        fuzzy_lib_path = pyimpfuzzy_path.parent / "bin" / "fuzzy.dll"

    fuzzy_lib = ctypes.cdll.LoadLibrary(str(fuzzy_lib_path))
    result_buf = ctypes.create_string_buffer(FUZZY_MAX_RESULT)
    data_buf = ctypes.create_string_buffer(data)
    fuzzy_lib.fuzzy_hash_buf(data_buf, len(data_buf) - 1, result_buf)
    hash_value = result_buf.value.decode("ascii")

    return hash_value

if len(sys.argv) == 4:
    hash_type = sys.argv[1]
    hash1 = sys.argv[2]
    hash2 = sys.argv[3]

    if hash_type == "compare-fuzzy":
        print(pyimpfuzzy.hash_compare(hash1, hash2), end="")
    elif hash_type == "compare-tlsh":
        print(tlsh.diff(hash1, hash2), end="")
elif len(sys.argv) == 2:
    hash_type = sys.argv[1]

    # Receive data
    data = sys.stdin.buffer.read()

    if hash_type == "ssdeep":
        print(ssdeep(data), end="")
    elif hash_type == "impfuzzy":
        file_type = magic.from_buffer(data)

        if file_type[:4] == "PE32":
            try:
                pe = None
                pe = pefile.PE(data=data)

                if pe and hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    print(pyimpfuzzy.get_impfuzzy_data(data), end="")
            except:
                pass # Do nothing if data is not valid PE file
    elif hash_type == "tlsh":
        print(tlsh.hash(data), end="")
else:
    # Receive data
    data = sys.stdin.buffer.read()

    print("")
    print("CRC32: %x" % (zlib.crc32(data) & 0xffffffff))
    print("MD5: %s" % hashlib.md5(data).hexdigest())
    print("SHA1: %s" % hashlib.sha1(data).hexdigest())
    print("SHA256: %s" % hashlib.sha256(data).hexdigest())
    print("ssdeep: %s" % ssdeep(data))
    tlsh_value = tlsh.hash(data)
    if tlsh_value == "TNULL":
        print("TLSH: %s (the file size is less than the minimum size (50 bytes))" % tlsh_value)
    else:
        print("TLSH: %s" % tlsh_value)

    file_type = magic.from_buffer(data)

    if file_type[:4] == "PE32":
        try:
            pe = None
            pe = pefile.PE(data=data)

            if pe and hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                imphash = pe.get_imphash()
                if imphash:
                    print("imphash: %s" % imphash)

                impfuzzy = pyimpfuzzy.get_impfuzzy_data(data)
                if impfuzzy:
                    print("impfuzzy: %s" % impfuzzy)

                exphash = pe.get_exphash()
                if exphash:
                    print("exphash: %s" % exphash)

                rich_header_hash = pe.get_rich_header_hash()
                if rich_header_hash:
                    print("Rich PE header hash: %s" % rich_header_hash)
        except:
            pass # Do nothing if data is not valid PE file
    elif file_type[:4] == "ELF ":
        try:
            # Create a temporary file
            fd, filepath = tempfile.mkstemp()
            handle = os.fdopen(fd, "wb")
            handle.write(data)
            handle.close()

            telfhash_dict = telfhash.telfhash(filepath)
            if telfhash_dict:
                if telfhash_dict[0]["msg"] != "":
                    print("telfhash: %s (%s)" % (telfhash_dict[0]["telfhash"], telfhash_dict[0]["msg"]))
                else:
                    print("telfhash: %s" % telfhash_dict[0]["telfhash"])
            os.remove(filepath) # Cleanup
        except Exception as e:
            print(e, file=sys.stderr)
            pass # Do nothing if data is not valid PE file
