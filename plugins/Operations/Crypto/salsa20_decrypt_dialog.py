#
# Salsa20 decrypt / encrypt - Decrypt / encrypt selected region with Salsa20
#
# Copyright (c) 2019, Nobutaka Mantani
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
import re
import sys
import tkinter
import tkinter.ttk
import tkinter.messagebox

sys.path.append("./lib")
import stream_cipher

try:
    import Cryptodome.Cipher.Salsa20
except ImportError:
    exit(-1) # PyCryptodome is not installed

class Salsa20DecryptDialog(stream_cipher.StreamCipherDialog):
    def process(self, **kwargs):
        key_type = self.combo_key_type.get()
        key = self.entry_key.get()
        nonce_type = self.combo_nonce_type.get()
        nonce = self.entry_nonce.get()

        if key_type == "Hex":
            if re.match("^([0-9A-Fa-f]{2})+$", key):
                key = binascii.a2b_hex(key)
            else:
                tkinter.messagebox.showerror("Error:", message="Key is not in hex format.")
                return
        else:
            key = key.encode()

        if nonce_type == "Hex":
            if re.match("^([0-9A-Fa-f]{2})+$", nonce):
                nonce = binascii.a2b_hex(nonce)
            else:
                tkinter.messagebox.showerror("Error:", message="Nonce is not in hex format.")
                return
        else:
            nonce = nonce.encode()

        if len(key) != 16 and len(key) != 32:
            tkinter.messagebox.showerror("Error:", message="Key size must be 16 bytes or 32 bytes.")
            return

        len_nonce = len(nonce)
        if len_nonce != 8:
            tkinter.messagebox.showerror("Error:", message="Nonce size must be 8 bytes.")
            return

        try:
            cipher = Cryptodome.Cipher.Salsa20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(self.data)
        except Exception as e:
            tkinter.messagebox.showerror("Error:", message=e)
            self.root.quit()
            exit(1) # Not decrypted

        sys.stdout.buffer.write(plaintext)
        self.root.quit()
        exit(0) # Decrypted successfully

if __name__ == "__main__":
    # Receive data
    data = sys.stdin.buffer.read()

    dialog = Salsa20DecryptDialog(title="Salsa20 decrypt / encrypt", data=data)
    dialog.show()
    exit(1) # Not decrypted
