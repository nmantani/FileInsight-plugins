#
# Compression operations - Various compression / decompression operations to
# selected region
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

import binascii
import bz2
import ctypes
import gzip
import os
import StringIO
import subprocess
import zlib

def aplib_compress(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        try:
            aplib = ctypes.windll.LoadLibrary("Compression/aplib.dll")

            compressed = ctypes.create_string_buffer(aplib.aP_max_packed_size(length))
            workspace = ctypes.create_string_buffer(aplib.aP_workmem_size(length))
            final_size = aplib.aPsafe_pack(ctypes.c_char_p(data), compressed, length, workspace, None, None)
            compressed = list(compressed)
            compressed = compressed[:final_size]

            newdata = orig[:offset]
            newdata.extend(compressed)
            newdata.extend(orig[offset + length:])

            fi.newDocument("Output of aPLib compress", 1)
            fi.setDocument("".join(newdata))
            fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

            if length == 1:
                print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
            else:
                print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
            print("Added a bookmark to compressed region.")
        except WindowsError:
            print("Error: cannot load aplib.dll.")
            print("Please download aPLib from http://ibsensoftware.com/download.html")
            print("and copy aplib.dll (32 bits version) into '%s' folder." % (os.getcwd() + "\\Compression"))

def aplib_decompress(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        try:
            aplib = ctypes.windll.LoadLibrary("Compression/aplib.dll")

            final_size = aplib.aPsafe_get_orig_size(ctypes.c_char_p(data))

            if final_size == -1:
                final_size = length
                count = 0
                ret = -1

                while (ret == -1 and count < 16):
                    final_size *= 2
                    uncompressed = ctypes.create_string_buffer(final_size)
                    ret = aplib.aP_depack_asm_safe(ctypes.c_char_p(data), length, uncompressed, final_size)
                    count +=1

                final_size = ret
            else:
                uncompressed = ctypes.create_string_buffer(final_size)
                final_size = aplib.aPsafe_depack(ctypes.c_char_p(data), length, uncompressed, final_size)

            if final_size == -1:
                raise Exception

            uncompressed = list(uncompressed)
            uncompressed = uncompressed[:final_size]

            newdata = orig[:offset]
            newdata.extend(uncompressed)
            newdata.extend(orig[offset + length:])

            fi.newDocument("Output of aPLib decompress", 1)
            fi.setDocument("".join(newdata))
            fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

            if length == 1:
                print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
            else:
                print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
            print("Added a bookmark to decompressed region.")

        except WindowsError:
            print("Error: cannot load aplib.dll")
            print("Please download aPLib from http://ibsensoftware.com/download.html")
            print("and copy aplib.dll (32 bits version) into '%s' folder." % (os.getcwd() + "\\Compression"))

        except Exception:
            print("Error: invalid compressed data")

def bzip2_compress(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        compressed = list(bz2.compress(data))
        final_size = len(compressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of Bzip2 compress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def bzip2_decompress(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        uncompressed = list(bz2.decompress(data))
        final_size = len(uncompressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = uncompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of Bzip2 decompress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")

def gzip_compress(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        strio = StringIO.StringIO()
        gz = gzip.GzipFile(fileobj=strio, mode="wb")
        gz.write(data)
        gz.close()
        compressed = strio.getvalue()
        final_size = len(compressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of Gzip compress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def gzip_decompress(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        strio = StringIO.StringIO(data)
        gz = gzip.GzipFile(fileobj=strio)
        decompressed = gz.read()
        final_size = len(decompressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = decompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of Gzip decompress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")

def lznt1_compress(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        compressed = ctypes.create_string_buffer(length * 13)
        work_size = ctypes.c_ulong(0)
        work_frag_size = ctypes.c_ulong(0)
        ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize(2, ctypes.byref(work_size), ctypes.byref(work_frag_size))
        workspace = ctypes.create_string_buffer(work_size.value)
        final_size = ctypes.c_ulong(0)

        ctypes.windll.ntdll.RtlCompressBuffer(2, ctypes.c_char_p(data), length, compressed, length * 3, 4096, ctypes.byref(final_size), workspace)
        compressed = list(compressed)
        newdata = [0] * (orig_len - (length - final_size.value))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size.value):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size.value + i] = orig[offset + length + i]

        fi.newDocument("Output of LZNT1 compress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size.value, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def lznt1_decompress(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        uncompressed = ctypes.create_string_buffer(length * 40)
        workspace = ctypes.create_string_buffer(length * 40)
        final_size = ctypes.c_ulong(0)

        ctypes.windll.ntdll.RtlDecompressBuffer(2, uncompressed, length * 3, ctypes.c_char_p(data), length, ctypes.byref(final_size))

        uncompressed = list(uncompressed)
        newdata = [0] * (orig_len - (length - final_size.value))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size.value):
            newdata[offset + i] = uncompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size.value + i] = orig[offset + length + i]

        fi.newDocument("Output of LZNT1 decompress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size.value, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")

def raw_deflate(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        compressed = list(zlib.compress(data))
        compressed = compressed[2:-4]
        final_size = len(compressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of Raw deflate", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def raw_inflate(fi):
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        decompressed = list(zlib.decompress(data, -15))
        final_size = len(decompressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = decompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of Raw inflate", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")

def lz4_compress(fi):
    """
    Compress selected region with LZ4 algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute lz4_compress.py for compression
        p = subprocess.Popen(["py.exe", "-3", "Compression/lz4_compress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive compressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        if ret == -1: # python-lz4 is not installed
            print("python-lz4 is not installed.")
            print("Please install it with 'py.exe -3 -m pip install lz4' and try again.")
            return

        compressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(compressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of LZ4 compress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def lz4_decompress(fi):
    """
    Decompress selected region with LZ4 algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute lz4_decompress.py for decompression
        p = subprocess.Popen(["py.exe", "-3", "Compression/lz4_decompress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive decompressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        if ret == -1: # python-lz4 is not installed
            print("python-lz4 is not installed.")
            print("Please install it with 'py.exe -3 -m pip install lz4' and try again.")
            return

        decompressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(decompressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = decompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of LZ4 decompress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")

def lzma_compress(fi):
    """
    Compress selected region with LZMA algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute lzma_compress.py for compression
        p = subprocess.Popen(["py.exe", "-3", "Compression/lzma_compress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive compressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        compressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(compressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of LZMA compress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def lzma_decompress(fi):
    """
    Decompress selected region with LZMA algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute lzma_decompress.py for decompression
        p = subprocess.Popen(["py.exe", "-3", "Compression/lzma_decompress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive decompressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        decompressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(decompressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = decompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of LZMA decompress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")

def xz_compress(fi):
    """
    Compress selected region with XZ format
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute xz_compress.py for compression
        p = subprocess.Popen(["py.exe", "-3", "Compression/xz_compress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive compressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        compressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(compressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of XZ compress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def xz_decompress(fi):
    """
    Decompress selected XZ compressed region
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute xz_decompress.py for decompression
        p = subprocess.Popen(["py.exe", "-3", "Compression/xz_decompress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive decompressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        decompressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(decompressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = decompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of XZ decompress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")

def zstandard_compress(fi):
    """
    Compress selected region with Zstandard algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute zstandard_compress.py for compression
        p = subprocess.Popen(["py.exe", "-3", "Compression/zstandard_compress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive compressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        if ret == -1: # python-zstandard is not installed
            print("python-zstandard is not installed.")
            print("Please install it with 'py.exe -3 -m pip install zstandard' and try again.")
            return

        compressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(compressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of Zstandard compress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def zstandard_decompress(fi):
    """
    Decompress selected region with Zstandard algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute zstandard_decompress.py for decompression
        p = subprocess.Popen(["py.exe", "-3", "Compression/zstandard_decompress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive decompressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        if ret == -1: # python-zstandard is not installed
            print("python-zstandard is not installed.")
            print("Please install it with 'py.exe -3 -m pip install zstandard' and try again.")
            return

        decompressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(decompressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = decompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of Zstandard decompress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")

def lzo_compress(fi):
    """
    Compress selected region with LZO algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute lzo_compress.py for compression
        p = subprocess.Popen(["py.exe", "-3", "Compression/lzo_compress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive compressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        if ret == -1: # python-lzo is not installed
            print("python-lzo is not installed.")
            print("Please manually download python-lzo wheel file (.whl) for your Python version")
            print("from 'https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-lzo' and install it with")
            print("'py.exe -3 -m pip install python_lzo-x.xx-cpxx-cpxx-win_amd64.whl', then try again.")
            return

        compressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(compressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = compressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of LZO compress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Compressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Compressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to compressed region.")

def lzo_decompress(fi):
    """
    Decompress selected region with LZO algorithm
    """
    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = list(fi.getDocument())
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute lzo_decompress.py for decompression
        p = subprocess.Popen(["py.exe", "-3", "Compression/lzo_decompress.py"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive decompressed data
        stdout_data, stderr_data = p.communicate(binascii.b2a_hex(data))
        ret = p.wait()

        if ret == -1: # python-lzo is not installed
            print("python-lzo is not installed.")
            print("Please manually download python-lzo wheel file (.whl) for your Python version")
            print("from 'https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-lzo' and install it with")
            print("'py.exe -3 -m pip install python_lzo-x.xx-cpxx-cpxx-win_amd64.whl', then try again.")
            return

        decompressed = list(binascii.a2b_hex(stdout_data))
        final_size = len(decompressed)
        newdata = [0] * (orig_len - (length - final_size))

        for i in range(0, offset):
            newdata[i] = orig[i]

        for i in range(0, final_size):
            newdata[offset + i] = decompressed[i]

        for i in range(0, orig_len - offset - length):
            newdata[offset + final_size + i] = orig[offset + length + i]

        fi.newDocument("Output of LZO decompress", 1)
        fi.setDocument("".join(newdata))
        fi.setBookmark(offset, final_size, hex(offset), "#c8ffff")

        if length == 1:
            print("Decompressed one byte from offset %s to %s." % (hex(offset), hex(offset)))
        else:
            print("Decompressed %s bytes from offset %s to %s." % (length, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decompressed region.")
