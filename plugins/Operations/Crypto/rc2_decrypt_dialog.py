#
# RC2 decrypt - Decrypt selected region with RC2
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
import block_cipher

try:
    import Cryptodome.Cipher.ARC2
    import Cryptodome.Util.Padding
except ImportError:
    exit(-1) # PyCryptodome is not installed

class RC2DecryptDialog(block_cipher.BlockCipherDialog):
    def process(self, **kwargs):
        arc2_mode = {"ECB":Cryptodome.Cipher.ARC2.MODE_ECB,
                    "CBC":Cryptodome.Cipher.ARC2.MODE_CBC,
                    "CFB":Cryptodome.Cipher.ARC2.MODE_CFB,
                    "OFB":Cryptodome.Cipher.ARC2.MODE_OFB,
                    "CTR":Cryptodome.Cipher.ARC2.MODE_CTR}

        mode = self.combo_mode.get()
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

        if mode in ["CBC", "CFB", "OFB"] and iv_type == "Hex":
            if re.match("^([0-9A-Fa-f]{2})+$", iv):
                iv = binascii.a2b_hex(iv)
            else:
                tkinter.messagebox.showerror("Error:", message="IV is not in hex format.")
                return
        else:
            iv = iv.encode()

        key_length = len(key)
        if key_length < 5 or key_length > 128:
            tkinter.messagebox.showerror("Error:", message="Key size must be in the range from 5 bytes and 128 bytes.")
            return

        if mode in ["CBC", "CFB", "OFB"] and len(iv) != Cryptodome.Cipher.ARC2.block_size:
            tkinter.messagebox.showerror("Error:", message="IV size must be %d bytes." % Cryptodome.Cipher.ARC2.block_size)
            return

        try:
            if mode == "CFB":
                cipher = Cryptodome.Cipher.ARC2.new(key, arc2_mode[mode], iv, segment_size=Cryptodome.Cipher.ARC2.block_size * 8)
            elif mode in ["CBC", "OFB"]:
                cipher = Cryptodome.Cipher.ARC2.new(key, arc2_mode[mode], iv)
            elif mode == "CTR": # The first half of IV is used as nonce and the second half is used as initial_value.
                cipher = Cryptodome.Cipher.ARC2.new(key, arc2_mode[mode], nonce=iv[0:4], initial_value=iv[4:8])
            else:
                cipher = Cryptodome.Cipher.ARC2.new(key, arc2_mode[mode])

            plaintext = cipher.decrypt(self.data)

            if mode in ["ECB", "CBC"]:
                plaintext = Cryptodome.Util.Padding.unpad(plaintext, Cryptodome.Cipher.ARC2.block_size)
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

    dialog = RC2DecryptDialog(title="RC2 decrypt", data=data)
    dialog.show()
    exit(1) # Not decrypted
