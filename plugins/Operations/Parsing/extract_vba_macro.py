#
# Extract VBA macro - Extract Microsoft Office VBA macro from selected region
# (the whole file if not selected)
#
# Copyright (c) 2023, Nobutaka Mantani
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

import os
import sys
import tempfile

try:
    import oletools.olevba
except ImportError:
    exit(-1) # oletools is not installed

try:
    import refinery.units.formats.office.vbapc
    import refinery.units.formats.office.xtvba
except ImportError:
    exit(-2) # Binary Refinery is not installed

if __name__ == "__main__":
    check_vba_stomping = False
    extract_from_pcode = False

    if len(sys.argv) == 2:
        if sys.argv[1] == "-c":
            check_vba_stomping = True

        if sys.argv[1] == "-p":
            extract_from_pcode = True

    # Receive data
    data = sys.stdin.buffer.read()

    # Check VBA stomping with oletools
    if check_vba_stomping:
        try:
            # Create a temporary file
            fd, filepath = tempfile.mkstemp()
            handle = os.fdopen(fd, "wb")
            handle.write(data)
            handle.close()

            parser = oletools.olevba.VBA_Parser(filename=filepath)
            vba_stomping = parser.detect_vba_stomping()

            os.remove(filepath) # Cleanup

            if vba_stomping:
                exit(1)
            else:
                exit(0)
        except Exception as e:
            print(e, file=sys.stderr)
            exit(0)

    try:
        if extract_from_pcode:
            parser = refinery.units.formats.office.vbapc.vbapc()
            extracted = parser.process(data=data)
        else:
            parser = refinery.units.formats.office.xtvba.xtvba()
            results = parser.unpack(data=data)

            extracted = b""
            for r in results:
                extracted += r.get_data()

        sys.stdout.buffer.write(extracted)
    except Exception as e:
        print(e, file=sys.stderr)
