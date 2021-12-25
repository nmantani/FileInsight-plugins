#
# Python implementation of LZRW1/KH compression algorithm
#
# This implementation is based on the C implementation by Kurt Haenen
# (http://www.dcee.net/Files/Programm/Packing/lzrw.arj)
# and the Delphi implementation by Danny Heijl
# (https://www.sac.sk/download/pack/tlzrw1.zip).
# This implementation is slow and not suitable for large files.
#
# Copyright (c) 2021, Nobutaka Mantani
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

import struct
import sys

HASH_SIZE = 4096
CHUNK_MAX = 32768 # Maximum chunk size of source file
FLAG_COMPRESS = 0x40
FLAG_COPIED = 0x80

# Format of compressed stream:
# [size of compressed chunk and flag (2 bytes, little endian)][flag (1 byte)][compressed chunk][size of compressed chunk and flag][flag][compressed chunk]...
#
# If compressed chunk is larger than original chunk, flag is set to FLAG_COPIED (0x80)
# and compressed chunk is replaced with copy of original chunk.
# Otherwise flag is set to FLAG_COMPRESS (0x40).
#
# Other implementations prepend file signature and original file size to compressed stream like this.
# [file signature (4 bytes)][original file size (4 bytes)][compressed stream]
#
# Kurt Haenen's implementation uses D8 C7 B6 A5 as file signature.
# Danny Heijl's implementaiion uses 57 52 5A 4C (WRZL).
#
# This implementation only compress / decompress stream and it does not use file signature and original file size.

# size and pos are list to use them with call by reference
def get_match(source_int, x, source_size, hash, size, pos):
    hash_value = (40543*((((source_int[x] << 4) ^ source_int[x + 1]) << 4) ^ source_int[x + 2]) >> 4) & 0xfff
    pos[0] = hash[hash_value]
    hash[hash_value] = x
    if (pos[0] != -1) and ((x - pos[0]) < HASH_SIZE):
        size[0] = 0
        while size[0] < 18 and (source_int[x + size[0]] == source_int[pos[0]+size[0]]) and ((x + size[0]) < source_size):
            size[0] += 1
        return size[0] >= 3
    return False

def compress(source):
    compressed = b""
    for i in range(0, len(source), CHUNK_MAX):
        chunk = source[i:i + CHUNK_MAX]
        output = compress_chunk(chunk)

        # Prepend size of compressed chunk (2 bytes, little endian)
        compressed += struct.pack("<H", len(output))
        compressed += output

    return compressed

def compress_chunk(source):

    bit = 0
    command = 0
    x = 0
    y = 3
    z = 1

    # size and pos are list to use them with call by reference
    size = [0]
    pos = [0]

    # Convert binary data into list of integer
    if sys.version_info.major == 2:
        source_int = [ord(i) for i in source]
    else:
        source_int = list(source)

    source_int += [0] * 15 # Extend list
    source_size = len(source)
    dest_int = [0] * len(source_int)

    hash = [-1] * HASH_SIZE
    dest_int[0] = FLAG_COMPRESS # Flag is stored at the beginning of compressed data

    while x < source_size and y <= source_size:
        if bit > 15:
            dest_int[z] = (command >> 8) & 0x00ff
            z += 1
            dest_int[z] = command & 0x00ff
            z = y
            bit = 0
            y += 2

        size[0] = 1
        while (source_int[x] == source_int[x + size[0]]) and (size[0] < 0x0fff) and (x + size[0] < source_size):
            size[0] += 1

        if size[0] >= 16:
            dest_int[y] = 0
            y += 1
            dest_int[y] = ((size[0] - 16) >> 8) & 0x00ff
            y += 1
            dest_int[y] = (size[0] - 16) & 0x00ff
            y += 1
            dest_int[y] = source_int[x]
            y += 1
            x += size[0]
            command = (command << 1) + 1
        elif get_match(source_int, x, source_size, hash, size, pos):
            key = ((x - pos[0]) << 4) + (size[0] - 3)
            dest_int[y] = (key >> 8) & 0x00ff
            y += 1
            dest_int[y] = key & 0x00ff
            y += 1
            x += size[0]
            command = (command << 1) + 1
        else:
            dest_int[y] = source_int[x]
            y += 1
            x += 1
            command = (command << 1)

        bit += 1

    command <<= (16 - bit)
    dest_int[z] = (command >> 8) & 0x00ff
    z += 1

    dest_int[z] = command & 0x00ff
    if y > source_size:
        # If compressed chunk is larger than original chunk,
        # FLAG_COPIED is set as flag and original chunk is appended.
        y = 0
        while y < source_size:
            dest_int[y + 1] = source_int[y]
            y += 1

        dest_int[0] = FLAG_COPIED
        # Convert into binary data
        if sys.version_info.major == 2:
            dest_bin = b"".join(map(chr, dest_int[:y + 1]))
        else:
            dest_bin = bytes(dest_int[:y + 1])

        return dest_bin
    else:
        # Convert into binary data
        if sys.version_info.major == 2:
            dest_bin = b"".join(map(chr, dest_int[:y]))
        else:
            dest_bin = bytes(dest_int[:y])

        return dest_bin

def decompress(source):
    decompressed = b""
    i = 0
    while i < len(source):
        # Get size of a chunk (2 bytes, little endian)
        chunk_size = struct.unpack("<H", source[i:i + 2])[0]
        decompressed += decompress_chunk(source[i + 2:i + 2 + chunk_size])
        i += 2 + chunk_size

    return decompressed

def decompress_chunk(source):
    x = 3
    y = 0
    k = 0
    bit = 16
    size = 0
    pos = 0

    if sys.version_info.major == 2:
        source_int = [ord(i) for i in source] # Convert binary data into list of integer
    else:
        source_int = list(source)

    source_size = len(source)
    if source_size > CHUNK_MAX:
        dest_int = [0] * (CHUNK_MAX + 15) * 2
    else:
        dest_int = [0] * (CHUNK_MAX + 15)

    command = (source_int[1] << 8) + source_int[2]

    if source_int[0] == FLAG_COPIED:
        # Convert into binary data
        if sys.version_info.major == 2:
            dest_bin = b"".join(map(chr, source_int[1:]))
        else:
            dest_bin = bytes(source_int[1:])

        return dest_bin

    while x < source_size:
        if bit == 0:
            command = (source_int[x] << 8)
            x += 1
            command += source_int[x]
            x += 1
            bit = 16
        if command & 0x8000:
            pos = (source_int[x] << 4)
            x += 1
            pos += (source_int[x] >> 4)

            if pos:
                size = (source_int[x] & 0x0f) + 3
                x += 1
                for k in range(0, size):
                    dest_int[y + k] = dest_int[y - pos + k]

                y += size
            else:
                size = (source_int[x] << 8)
                x += 1
                size += source_int[x] + 16
                x += 1

                k = 0
                while k < size:
                    dest_int[y + k] = source_int[x]
                    k += 1

                x += 1
                y += size
        else:
            dest_int[y] = source_int[x]
            y += 1
            x += 1

        command <<= 1
        bit -= 1

    # Convert into binary data
    if sys.version_info.major == 2:
        dest_bin = b"".join(map(chr, dest_int[:y]))
    else:
        dest_bin = bytes(dest_int[:y])

    return dest_bin
