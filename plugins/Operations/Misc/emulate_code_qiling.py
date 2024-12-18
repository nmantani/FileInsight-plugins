#
# Emulate code - Emulate selected region as an executable or shellcode
# (the whole file if not selected)
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

import os
import pathlib
import shlex
import sys

try:
    import packaging.version
except ImportError:
    sys.exit(-1) # packaging is not installed

try:
    import qiling
except ImportError:
    sys.exit(-2) # Qiling Framework is not installed

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    sys.exit(-3) # watchdog is not installed

rootfs_base = "Misc\\qiling-master\\examples\\rootfs"

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self):
        super(FileChangeHandler, self).__init__()
        self.log = ""

    def on_created(self, event):
        self.log += "[Created] %s\n" % pathlib.Path(event.src_path).resolve()

    def on_deleted(self, event):
        self.log += "[Deleted] %s\n" % pathlib.Path(event.src_path).resolve()

    def on_modified(self, event):
        # Ignore change of last accesss timestamp
        if event.is_directory == False:
            self.log += "[Modified] %s\n" % pathlib.Path(event.src_path).resolve()

    def on_moved(self, event):
        self.log += "[Moved] %s -> %s\n" % (pathlib.Path(event.src_path).resolve(), pathlib.Path(event.dest_path).resolve())

    def show_log(self):
        if self.log != "":
            print("\nFile system events in rootfs (creation, deletion, modification and move):", file=sys.stderr)
            print(self.log, end="", file=sys.stderr)

def rootfs_path(base, arch, os_type, big_endian):
    if arch == "arm":
        if big_endian == True:
            rootfs = base + "\\armeb_%s" % os_type
        else:
            rootfs = base + "\\arm_%s" % os_type
    elif arch == "mips":
        if big_endian == True:
            rootfs = base + "\\mips32_%s" % os_type
        else:
            rootfs = base + "\\mips32el_%s" % os_type
    else:
        rootfs = base + "\\%s_%s" % (arch, os_type)

    if pathlib.Path(rootfs).exists():
        return rootfs
    else:
        print("Error: rootfs %s is not found." % rootfs, file=sys.stderr)
        print("This combination of OS and architecture is is not supported.", file=sys.stderr)
        return None

def check_rootfs_files(rootfs_base):
    rootfs_ok = True

    for f in ["kernel32.dll", "ntoskrnl.exe"]: # ntoskrnl.exe is required since Qiling Framework 1.2
        if not pathlib.Path(rootfs_base + "\\x8664_windows\\Windows\\System32\\" + f).exists():
            print("%s is not found in %s ." % (f, pathlib.Path(rootfs_base + "\\x8664_windows\\Windows\\System32").resolve()), file=sys.stderr)
            rootfs_ok = False
        if not pathlib.Path(rootfs_base + "\\x86_windows\\Windows\\System32\\" + f).exists():
            print("%s is not found in %s ." % (f, pathlib.Path(rootfs_base + "\\x86_windows\\Windows\\System32").resolve()), file=sys.stderr)
            rootfs_ok = False

    if not pathlib.Path(rootfs_base + "\\x86_windows\\Windows\\System32\\ucrtbase.dll").exists():
        print("ucrtbase.dll is not found in %s ." % pathlib.Path(rootfs_base + "\\x86_windows\\Windows\\System32").resolve(), file=sys.stderr)
        rootfs_ok = False

    # ntdll.dll must be placed in System32 folder for Windows (x86) since Qiling Framework 1.2.2
    if not pathlib.Path(rootfs_base + "\\x86_windows\\Windows\\System32\\ntdll.dll").exists():
        print("ntdll.dll is not found in %s ." % pathlib.Path(rootfs_base + "\\x86_windows\\Windows\\System32").resolve(), file=sys.stderr)
        rootfs_ok = False

    if rootfs_ok == False:
        print("\nSince Qiling Framework 1.2.2, the location of x86 Windows DLL files has been changed from\n%s\nto\n%s ." % (pathlib.Path(rootfs_base + "\\x86_windows\\Windows\\SysWOW64").resolve(), pathlib.Path(rootfs_base + "\\x86_windows\\Windows\\System32").resolve()), file=sys.stderr)

    if not pathlib.Path(rootfs_base + "\\x8664_linux\\lib\\libc.so.6").exists():
        print("libc.so.6 is not found in %s ." % pathlib.Path(rootfs_base + "\\x8664_linux\\lib").resolve(), file=sys.stderr)
        rootfs_ok = False
    if not pathlib.Path(rootfs_base + "\\x86_linux\\lib\\libc.so.6").exists():
        print("libc.so.6 is not found in %s ." % pathlib.Path(rootfs_base + "\\x86_linux\\lib").resolve(), file=sys.stderr)
        rootfs_ok = False

    return rootfs_ok

# Hook of execve system call to get memory data, this is necessary since Qiling Framework 1.2.2
def execve_hook(ql, execve_pathname, execve_argv, execve_envp):
    import qiling.os.posix.syscall.unistd
    global all_mem, map_info

    # save all_mem and map_info before they will be lost in ql_syscall_execve()
    all_mem = ql.mem.save()
    map_info = ql.mem.map_info

    vpath = ql.os.utils.read_cstring(execve_pathname)
    hpath = ql.os.path.virtual_to_host_path(vpath)

    # ql_syscall_execve() does not show log message if these conditions are not met
    if not ql.os.path.is_safe_host_path(hpath) or not os.path.isfile(hpath):
        def __read_ptr_array(addr):
            if addr:
                while True:
                    elem = ql.mem.read_ptr(addr)

                    if elem == 0:
                        break

                    yield elem
                    addr += ql.arch.pointersize

        def __read_str_array(addr):
            yield from (ql.os.utils.read_cstring(ptr) for ptr in __read_ptr_array(addr))

        args = list(__read_str_array(execve_argv))

        env = {}
        for s in __read_str_array(execve_envp):
            k, _, v = s.partition('=')
            env[k] = v

        ql.stop()
        ql.clear_ql_hooks()

        ql.log.debug(f"execve system call is hooked with execve_hook() function to get memory dumps")
        ql.log.debug(f'execve("{vpath}", [{", ".join(args)}], [{", ".join(f"{k}={v}" for k, v in env.items())}])')
    else:
        qiling.os.posix.syscall.unistd.ql_syscall_execve(ql, execve_pathname, execve_argv, execve_envp)

if __name__ == "__main__":
    if len(sys.argv) == 10:
        file_path = sys.argv[1]
        file_type = sys.argv[2].lower()
        os_type = sys.argv[3].lower()
        arch = sys.argv[4]
        if arch == "x64":
            arch = "x8664"
        elif arch == "risc-v32":
            arch = "riscv32"
        elif arch == "risc-v64":
            arch = "riscv64"
        big_endian = sys.argv[5]
        if big_endian == "True":
            big_endian = True
        else:
            big_endian = False
        cmd_args = shlex.split(sys.argv[6])
        multithread = sys.argv[7]
        if multithread == "True":
            multithread = True
        else:
            multithread = False
        timeout = int(sys.argv[8])
        tab_index = int(sys.argv[9])

        if not check_rootfs_files(rootfs_base):
            sys.exit(-4) # rootfs files are not properly set up

        rootfs = rootfs_path(rootfs_base, arch, os_type, big_endian)

        if rootfs == None:
            print("Abort emulation.", file=sys.stderr)
            sys.exit(1)

        if file_type == "executable":
            try:
                from qiling.const import QL_VERBOSE

                ql = qiling.Qiling(argv=[file_path] + cmd_args, rootfs=rootfs, multithread=multithread, verbose=QL_VERBOSE.DEBUG, profile="%s.ql" % os_type)

                # Start to watch file system events
                handler = FileChangeHandler()
                observer = Observer()
                observer.schedule(handler, rootfs_base, recursive=True)
                observer.start()
            except Exception as e:
                print("Emulation aborted.", file=sys.stderr)
                print("Error: %s" % e, file=sys.stderr)
                sys.exit(1)
        else: # shellcode
            # Receive code from temporary file
            with open(file_path, "rb") as f:
                shellcode = f.read()

            try:
                from qiling.const import QL_ENDIAN, QL_ARCH, QL_OS, QL_INTERCEPT, QL_VERBOSE

                if big_endian:
                    endian = QL_ENDIAN.EB
                else:
                    endian = QL_ENDIAN.EL

                dict_arch = {"x86": QL_ARCH.X86,
                             "x8664": QL_ARCH.X8664,
                             "arm": QL_ARCH.ARM,
                             "arm64": QL_ARCH.ARM64,
                             "mips": QL_ARCH.MIPS,
                             "riscv32": QL_ARCH.RISCV,
                             "riscv64": QL_ARCH.RISCV64}

                dict_os = {"linux": QL_OS.LINUX, "windows": QL_OS.WINDOWS}

                ql = qiling.Qiling(code=shellcode, archtype=dict_arch[arch], ostype=dict_os[os_type], rootfs=rootfs, endian=endian, multithread=multithread, verbose=QL_VERBOSE.DEBUG)

                if os_type == "linux":
                    ql.os.set_syscall("execve", execve_hook, QL_INTERCEPT.CALL)

                # Start to watch file system events
                handler = FileChangeHandler()
                observer = Observer()
                observer.schedule(handler, rootfs_base, recursive=True)
                observer.start()
            except Exception as e:
                print("Emulation aborted.", file=sys.stderr)
                print("Error: %s" % e, file=sys.stderr)
                sys.exit(1)
    else:
        print(sys.argv, file=sys.stderr)
        print("Usage: emulate_code_qiling.py file_path file_type os arch big_endian cmd_args multithread timeout tab_index", file=sys.stderr)
        sys.exit(1)

    all_mem = None
    map_info = None

    # Ignore emulation error
    try:
        if timeout > 0:
            ql.run(timeout=1000000 * timeout) # timeout must be set as microseconds
        else:
            ql.run()
        observer.stop()
        observer.join()
    except Exception as e:
        print("Error: %s" % e, file=sys.stderr)

    # execve_hook was called
    if all_mem != None:
        ql.mem.map_info = map_info
    else:
        all_mem = ql.mem.save()

    print("\nMemory map:", file=sys.stderr)
    for info_line in ql.mem.get_formatted_mapinfo():
        print(info_line, file=sys.stderr)
    print("", file=sys.stderr)

    num_dump = 0
    heap = ""
    heap_start = None
    heap_end = None

    all_mem = all_mem["ram"]
    start_index = 0

    for i in range(start_index, len(all_mem) + start_index):
        start = all_mem[i][0]
        end = all_mem[i][1]
        info = all_mem[i][3]
        image = ql.loader.find_containing_image(start)

        if image:
            info += " (%s)" % image.path

        if file_path in info or info in ("[shellcode]", "[shellcode_base]", "[shellcode_stack]", "[stack]", "[brk]"):
            print('Extracted region %s (start: 0x%x end: 0x%x size: %d) as "Memory dump %d - %d"' % (info, start, end, end - start, tab_index, num_dump), file=sys.stderr)
            sys.stdout.buffer.write(b"****MEMDUMP****" + ql.mem.read(start, end - start))
            num_dump += 1
        elif info == "[heap]":
            # Concatenate multiple heap regions
            if heap_start == None:
                heap = b"****MEMDUMP****"
                heap_start = start
            if heap_end == None or end > heap_end:
                heap_end = end
            heap += ql.mem.read(start, end - start)

    if len(heap) > 0:
        print('Extracted region [heap] (start: 0x%x end: 0x%x size: %d) as "Memory dump %d - %d"' % (heap_start, heap_end, heap_end - heap_start, tab_index, num_dump), file=sys.stderr)
        sys.stdout.buffer.write(heap)

    handler.show_log()

    print("", file=sys.stderr)
    sys.exit(0)
