#
# Visualization operations
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

import math
import os
import subprocess
import tempfile

def byte_histogram(fi):
    """
    Show byte histogram of selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Check existence of matplotlib and seaborn
    # "pip list" is used for checking because imporing seaborn takes a few seconds
    p = subprocess.Popen([fi.get_venv_python(), "-m", "pip", "list"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    if "matplotlib" not in stdout_data:
        fi.show_module_install_instruction("matplotlib")
        return
    elif "seaborn" not in stdout_data:
        fi.show_module_install_instruction("seaborn")
        return

    tab_name = fi.get_new_document_name("Byte frequency")

    if length > 0:
        whole_file = False
        data = fi.getSelection()
        print('Byte frequency from offset %s to %s (descending order by count) is shown in the new "%s" tab.' % (hex(offset), hex(offset + length - 1), tab_name))
    else:
        whole_file = True
        data = fi.getDocument()
        length = fi.getLength()
        print('Byte frequency of the whole file (descending order by count) is shown in the new "%s" tab.' % tab_name)

    freq = {}

    for i in range(0, 256):
        freq[i] = 0

    for i in range(0, length):
        v = ord(data[i])
        freq[v] += 1

    output = ""
    for k, v in sorted(freq.items(), key=lambda x:x[1], reverse=True):
        output += "0x%02X: %d\n" % (k, v)
    fi.newDocument(tab_name, 0)
    fi.setDocument(output)

    # Create a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "w")
    output = []
    for i in range(0, 256):
        output.append(str(freq[i]))
    handle.write("\t".join(output))
    handle.close()

    if whole_file:
        print("Creating a byte histogram of the whole file in a background process...")
    else:
        print("Creating a byte histogram from offset %s to %s in a background process..." % (hex(offset), hex(offset + length - 1)))

    # Execute byte_histogram.py to show histogram
    p = subprocess.Popen([fi.get_venv_python(), "Visualization/byte_histogram.py", filepath], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def bitmap_view(fi):
    """
    Visualize the whole file as bitmap representation
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
        return

    data = fi.getDocument()

    # Create a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "w")
    handle.write(data)
    handle.close()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Check existence of Pillow
    p = subprocess.Popen([fi.get_venv_python(), "Visualization/bitmap_view.py", "-c"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ret = p.wait()

    if ret == -1: # Pillow is not installed
        fi.show_module_install_instruction("PIL", "Pillow")
        return

    print("Sending the whole file to the viewer GUI.")
    print("You can move window by dragging bitmap image.")
    print("You can also copy current offset by right-clicking bitmap image.")

    # Execute bitmap_view.py to show GUI in background
    p = subprocess.Popen([fi.get_venv_python(), "Visualization/bitmap_view.py", filepath], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def entropy(data):
    """
    Calculate entropy, used by entropy_graph()
    """
    h = 0
    bins = [0 for x in range(0, 256)]
    length = len(data)

    for v in data:
        bins[ord(v)] += 1

    for x in range(0, 256):
        p_x = float(bins[x]) / length
        if p_x > 0:
            h += - p_x * math.log(p_x, 2)

    return h

def entropy_graph(fi):
    """
    Show entropy graph of selected region (the whole file if not selected)
    """
    if fi.getDocumentCount() == 0:
        print("Please open a file to use this plugin.")
        return

    length = fi.getSelectionLength()
    offset = fi.getSelectionOffset()

    # Do not show command prompt window
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    # Check existence of matplotlib and seaborn
    # "pip list" is used for checking because imporing seaborn takes a few seconds
    p = subprocess.Popen([fi.get_venv_python(), "-m", "pip", "list"], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_data, stderr_data = p.communicate()
    ret = p.wait()

    if "matplotlib" not in stdout_data:
        fi.show_module_install_instruction("matplotlib")
        return
    elif "seaborn" not in stdout_data:
        fi.show_module_install_instruction("seaborn")
        return

    # Calculate overall entropy
    if length > 0:
        whole_file = False
        data = fi.getSelection()
        h = entropy(data)
        print("Entropy from offset %s to %s: %f" % (hex(offset), hex(offset + length - 1), h))
    else:
        whole_file = True
        data = fi.getDocument()
        length = fi.getLength()
        offset = 0
        h = entropy(data)
        print("Entropy of the whole file: %f" % h)
    print("")

    num_block = 256
    blocksize = length // num_block
    if blocksize > 256:
        blocksize -= blocksize % 256 # round blocksize

    if blocksize == 0:
        print("Error: file size is too small.")
        return

    block_offset = 0
    values = [str(offset), str(blocksize)]
    while block_offset < length:
        # Discard the last block if its size is less than half of blocksize
        if len(data[block_offset:block_offset+blocksize]) > blocksize // 2:
            values.append(str(entropy(data[block_offset:block_offset+blocksize])))
        block_offset += blocksize

    # Write entropy values to a temporary file
    fd, filepath = tempfile.mkstemp()
    handle = os.fdopen(fd, "w")
    handle.write("\t".join(values))
    handle.close()

    if whole_file:
        print("Creating an entropy graph of the whole file in a background process...")
    else:
        print("Creating an entropy graph from offset %s to %s in a background process..." % (hex(offset), hex(offset + length - 1)))

    # Execute entropy_graph.py to show graph
    p = subprocess.Popen([fi.get_venv_python(), "Visualization/entropy_graph.py", filepath], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
