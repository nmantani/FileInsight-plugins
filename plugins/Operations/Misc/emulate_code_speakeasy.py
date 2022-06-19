#
# Emulate code - Emulate selected region as an executable or shellcode
# (the whole file if not selected)
#
# Copyright (c) 2022, Nobutaka Mantani
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

import hashlib
import json
import logging
import os
import shlex
import sys

def get_logger():
    logger = logging.getLogger("speakeasy")
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.INFO)

    return logger

def all_zero(data):
    for d in data:
        if d != 0:
            return False

    return True

try:
    import speakeasy
except ImportError:
    sys.exit(-5) # speakeasy is not installed

if len(sys.argv) == 8:
    file_path = sys.argv[1]
    file_type = sys.argv[2].lower()
    os_type = sys.argv[3].lower()
    arch = sys.argv[4]
    if arch == "x64":
        arch = "amd64"
    cmd_args = shlex.split(sys.argv[5])
    timeout = int(sys.argv[6])
    tab_index = int(sys.argv[7])

    try:
        logger = get_logger()
        se = speakeasy.Speakeasy(argv=cmd_args, logger=logger)
        se.config.update({"timeout": timeout, "analysis": {"memory_tracing": True, "strings": False}, "keep_memory_on_free": True})

        if file_type == "executable":
            module = se.load_module(file_path)
            se.run_module(module)
        else: # shellcode
            sc_addr = se.load_shellcode(file_path, arch)
            se.run_shellcode(sc_addr, offset=0)

        #print("", file=sys.stderr)
        #print("Memory map:", file=sys.stderr)
        manifest = []
        loaded_bins = [os.path.splitext(os.path.basename(b))[0] for b in se.loaded_bins]
        procs = []
        [procs.append(block[4]) for block in se.get_memory_dumps() if block[4] not in procs]
        num_dump = 0
        dump_msg = ""

        for process in procs:
            memory_blocks = []
            if process:
                pid = process.get_pid()
                path = process.get_process_path()
            else:
                continue

            #print("Start              End                is_free\tTag", file=sys.stderr)
            manifest.append({"pid": pid, "process_name": path, "arch": arch,
                             "memory_blocks": memory_blocks})
            for block in se.get_memory_dumps():
                tag, base, size, is_free, _proc, data = block

                # Add stack to memory dumps
                if tag and tag.startswith("emu.stack."):
                    pass
                else:
                    if not tag:
                        continue
                    if _proc != process:
                        continue
                    # Ignore emulator noise such as structures created by the emulator, or
                    # modules that were loaded
                    if tag and tag.startswith("emu") and not tag.startswith("emu.shellcode."):
                        bns = [b for b in loaded_bins if b in tag]
                        if not len(bns):
                            continue

                h = hashlib.sha256()
                h.update(data)
                _hash = h.hexdigest()

                file_name = '%s.mem' % (tag)

                memory_blocks.append({"tag":  tag, "base": hex(base), "size": hex(size),
                                      "is_free": is_free, "sha256": _hash,
                                      "file_name": file_name, "data": data})

        print("", file=sys.stderr)
        print("Memory map:", file=sys.stderr)
        print("Start              End                is_free\tTag", file=sys.stderr)
        for m in manifest:
            b = m["memory_blocks"][0]
            tag = b["tag"]
            base = int(b["base"], 16)
            size = int(b["size"], 16)
            is_free = b["is_free"]
            dump_start = base
            dump_end = base + size
            dump_size = size
            dump_tag = tag
            dump_num_block = 1
            print("0x%014x - 0x%014x   %s   \t%s" % (base, base + size, is_free, tag), file=sys.stderr)
            dump_data = b["data"]
            del(b["data"])

            # Sort memory blocks except the first block
            consecutive = False
            for b in sorted(m["memory_blocks"][1:], key=lambda x: int(x["base"], 16)):
                tag = b["tag"]
                base = int(b["base"], 16)
                size = int(b["size"], 16)
                is_free = b["is_free"]
                print("0x%014x - 0x%014x   %s   \t%s" % (base, base + size, is_free, tag), file=sys.stderr)

                if dump_end == base:
                    consecutive = True
                    dump_data += b["data"]
                    dump_end = base + size
                    dump_size += size
                    dump_num_block += 1
                else:
                    consecutive = False

                    if all_zero(dump_data):
                        if dump_num_block > 1:
                            dump_msg += 'The region %s and consecutive regions (start: 0x%x end: 0x%x size: %d) contain only zero. Extraction is skipped."\n' % (dump_tag, dump_start,  dump_end, dump_size)
                        else:
                            dump_msg += 'The region %s (start: 0x%x end: 0x%x size: %d) contains only zero. Extraction is skipped."\n' % (dump_tag, dump_start, dump_end, dump_size)
                    else:
                        sys.stdout.buffer.write(b"****MEMDUMP****" + dump_data)

                        if dump_num_block > 1:
                            dump_msg += 'Extracted region %s and consecutive regions (start: 0x%x end: 0x%x size: %d) as "Memory dump %d - %d"\n' % (dump_tag, dump_start,  dump_end, dump_size, tab_index, num_dump)
                        else:
                            dump_msg += 'Extracted region %s (start: 0x%x end: 0x%x size: %d) as "Memory dump %d - %d"\n' % (dump_tag, dump_start, dump_end, dump_size, tab_index, num_dump)

                        num_dump += 1

                    dump_data = b["data"]
                    dump_start = base
                    dump_end = base + size
                    dump_size = size
                    dump_tag = tag
                    dump_num_block = 1

                del(b["data"])

        if all_zero(dump_data):
            if dump_num_block > 1:
                dump_msg += 'The region %s and consecutive regions (start: 0x%x end: 0x%x size: %d) contain only zero. Extraction is skipped."\n' % (dump_tag, dump_start,  dump_end, dump_size)
            else:
                dump_msg += 'The region %s (start: 0x%x end: 0x%x size: %d) contains only zero. Extraction is skipped."\n' % (dump_tag, dump_start, dump_end, dump_size)
        else:
            sys.stdout.buffer.write(b"****MEMDUMP****" + dump_data)
            if dump_num_block > 1:
                dump_msg += 'Extracted region %s and consecutive regions (start: 0x%x end: 0x%x size: %d) as "Memory dump %d - %d"\n' % (dump_tag, dump_start, dump_end, dump_size, tab_index, num_dump)
            else:
                dump_msg += 'Extracted region %s (start: 0x%x end: 0x%x size: %d) as "Memory dump %d - %d"\n' % (dump_tag, dump_start, dump_end, dump_size, tab_index, num_dump)

        print("", file=sys.stderr)
        print(dump_msg, file=sys.stderr)
        print("Emulation report (JSON format, compatible with speakeasy cli):", file=sys.stderr)
        report = se.get_json_report()
        print(report, file=sys.stderr)
        print("", file=sys.stderr)
        print("Memory dump manifest (JSON format, compatible with speakeasy cli):", file=sys.stderr)
        manifest = json.dumps(manifest, indent=4, sort_keys=False)
        print(manifest, file=sys.stderr)
    except Exception as e:
        print("Emulation aborted.", file=sys.stderr)
        print("Error: %s" % e, file=sys.stderr)
        sys.exit(1)
