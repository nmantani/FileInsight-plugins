#
# Camellia encrypt - Encrypt selected region with Camellia
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

import binascii
import re
import sys
import tkinter
import tkinter.messagebox

sys.path.append("./lib")
import block_cipher

try:
    import refinery.units.crypto.cipher.camellia
except ImportError:
    exit(-2) # Binary Refinery is not installed

class CamelliaEncryptDialog(block_cipher.BlockCipherDialog):
    def process(self, **kwargs):
        camellia_key_size = (16, 24, 32)
        blocksize_bits = 128

        mode = self.combo_mode.get()
        key_size = camellia_key_size[self.combo_key_length.current()]
        key_type = self.combo_key_type.get()
        key = self.entry_key.get()
        iv_type = self.combo_iv_type.get()
        iv = self.entry_iv.get()

        if key_type == "Hex":
            if re.match("^([0-9A-Fa-f]{2})+$", key):
                key = binascii.a2b_hex(key)
            else:
                tkinter.messagebox.showerror("Error:", message="Key is not in hex format.")
                return
        else:
            key = key.encode()

        if mode in ["CBC", "CFB", "OFB", "CTR"] and iv_type == "Hex":
            if re.match("^([0-9A-Fa-f]{2})+$", iv):
                iv = binascii.a2b_hex(iv)
            else:
                tkinter.messagebox.showerror("Error:", message="IV is not in hex format.")
                return
        else:
            iv = iv.encode()

        if len(key) != key_size:
            tkinter.messagebox.showerror("Error:", message="Key size must be %d bytes." % key_size)
            return

        if mode in ["CBC", "CFB", "OFB", "CTR"] and len(iv) != 16: # 128 bits
            tkinter.messagebox.showerror("Error:", message="IV size must be 16 bytes.")
            return

        try:
            if mode in ["OFB", "CTR"]:
                cipher = refinery.units.crypto.cipher.camellia.camellia(key=key, iv=iv, mode=mode)
            elif mode == "CFB":
                segment_size = blocksize_bits
                cipher = refinery.units.crypto.cipher.camellia.camellia(key=key, iv=iv, mode=mode, segment_size=segment_size)
            elif mode == "CBC":
                cipher = refinery.units.crypto.cipher.camellia.camellia(key=key, iv=iv, padding="pkcs7", mode=mode)
            elif mode == "ECB":
                cipher = refinery.units.crypto.cipher.camellia.camellia(key=key, padding="pkcs7", mode=mode)

            ciphertext = cipher.reverse(data=self.data)
        except Exception as e:
            tkinter.messagebox.showerror("Error:", message=e)
            self.root.quit()
            exit(1) # Not encrypted

        sys.stdout.buffer.write(ciphertext)
        self.root.quit()
        exit(0) # Encrypted successfully

if __name__ == "__main__":
    # Receive data
    data = sys.stdin.buffer.read()

    dialog = CamelliaEncryptDialog(title="Camellia encrypt", data=data, use_key_length=True)
    dialog.show()
    exit(1) # Not decrypted
