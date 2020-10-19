#
# Emulate code - Emulate selected region as an executable or shellcode
# with Qiling Framework (the whole file if not selected)
#
# Copyright (c) 2020, Nobutaka Mantani
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

import binascii
import os
import shlex
import sys
import tempfile

try:
    import qiling
except ImportError:
    sys.exit(-1) # Qiling Framework is not installed

def rootfs_path(arch, os_type, big_endian):
    if arch == "arm":
        if big_endian == True:
            rootfs = "Misc\\qiling-master\\examples\\rootfs\\armeb_%s" % os_type
        else:
            rootfs = "Misc\\qiling-master\\examples\\rootfs\\arm_%s" % os_type
    elif arch == "mips":
        if big_endian == True:
            rootfs = "Misc\\qiling-master\\examples\\rootfs\\mips32_%s" % os_type
        else:
            rootfs = "Misc\\qiling-master\\examples\\rootfs\\mips32el_%s" % os_type
    else:
        rootfs = "Misc\\qiling-master\\examples\\rootfs\\%s_%s" % (arch, os_type)

    if os.path.exists(rootfs):
        return rootfs
    else:
        print("Error: rootfs %s not found." % rootfs, file=sys.stderr)
        return None

if len(sys.argv) == 7:
    file_path = sys.argv[1]
    file_type = sys.argv[2].lower()
    os_type = sys.argv[3].lower()
    arch = sys.argv[4]
    if arch == "x64":
        arch = "x8664"
    big_endian = sys.argv[5]
    if big_endian == "True":
        big_endian = True
    else:
        big_endian = False
    cmd_args = shlex.split(sys.argv[6])

    if not os.path.exists("Misc\\qiling-master\\examples\\rootfs\\x8664_windows\\Windows\\System32\\kernel32.dll"):
        sys.exit(-2) # Windows DLL files are not properly set up

    rootfs = rootfs_path(arch, os_type, big_endian)

    if rootfs == None:
        print("Abort emulation.", file=sys.stderr)
        sys.exit(1)

    if file_type == "executable":
        try:
            ql = qiling.Qiling(filename=[file_path] + cmd_args, rootfs=rootfs, output="debug", profile="%s.ql" % os_type)
        except Exception as e:
            print("Emulation aborted.", file=sys.stderr)
            print("Error: %s" % e, file=sys.stderr)
            sys.exit(1)
    else: # shellcode
        # Receive code from temporary file
        with open(file_path, "rb") as f:
            shellcode = f.read()

        try:
            ql = qiling.Qiling(shellcoder=shellcode, archtype=arch, ostype=os_type, rootfs=rootfs, bigendian=big_endian, output="debug")
        except Exception as e:
            print("Emulation aborted.", file=sys.stderr)
            print("Error: %s" % e, file=sys.stderr)
            sys.exit(1)
else:
    print("Usage: emulate_code.py file_path file_type os arch big_endian cmd_args", file=sys.stderr)
    sys.exit(1)

# Ignore emulation error
try:
    ql.run()
except Exception as e:
    print("Error: %s" % e, file=sys.stderr)

all_mem = ql.mem.save()
print("\nMemory map:", file=sys.stderr)
ql.mem.show_mapinfo()
print("", file=sys.stderr)

num_dump = 0
heap = ""
heap_start = None
heap_end = None
for i in range(1, len(all_mem) + 1):
    start = all_mem[i][0]
    end = all_mem[i][1]
    info = all_mem[i][3]
    image = ql.os.find_containing_image(start)
    if image:
        info += " (%s)" % image.path

    if file_path in info or info in ("[shellcode_base]", "[shellcode_stack]", "[stack]"):
        print("Extracted region %s (start: 0x%x end: 0x%x size: %d) as Memory dump %d" % (info, start, end, end - start, num_dump), file=sys.stderr)
        print("****MEMDUMP****" + binascii.b2a_hex(ql.mem.read(start, end - start)).decode(), end="")
        num_dump += 1
    elif info == "[heap]":
        # Concatenate multiple heap regions
        if heap_start == None:
            heap = "****MEMDUMP****"
            heap_start = start
        if heap_end == None or end > heap_end:
            heap_end = end
        heap += binascii.b2a_hex(ql.mem.read(start, end - start)).decode()

if len(heap) > 0:
    print("Extracted region [heap] (start: 0x%x end: 0x%x size: %d) as Memory dump %d" % (heap_start, heap_end, heap_end - heap_start, num_dump), file=sys.stderr)
    print(heap, end="")

print("", file=sys.stderr)
sys.exit(0)
