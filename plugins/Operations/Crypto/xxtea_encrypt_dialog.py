#
# XXTEA encrypt - Encrypt selected region with XXTEA (Corrected Block Tiny Encryption Algorithm)
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

import binascii
import re
import sys
import tkinter
import tkinter.ttk
import tkinter.messagebox

sys.path.append("./lib")
import block_cipher

try:
    import refinery.units.crypto.cipher.xxtea
except ImportError:
    exit(-2) # Binary Refinery is not installed

class XXTEAEncryptDialog(block_cipher.TEADialogBase):
    def process(self, **kwargs):
        key_size = 16

        mode = self.combo_mode.get()
        endianness = self.combo_endianness.get()
        key_type = self.combo_key_type.get()
        key = self.entry_key.get()
        iv_type = self.combo_iv_type.get()
        iv = self.entry_iv.get()
        single_block = self.bool_single_block.get()

        if single_block == True:
            # Treat input data as a single block
            if mode == "CTR":
                tkinter.messagebox.showerror("Error:", message="Treating input data as a single block is not supported with CTR mode.")
                return

            block_size = 1

            if len(self.data) % 4 == 0:
                block_size_bytes = len(self.data)
            else:
                block_size_bytes = ((len(self.data) // 4) + 1) * 4
        else:
            block_size_bytes = int(self.block_size.get())

            # Block size in 32-bit words
            if block_size_bytes % 4 == 0:
                block_size = block_size_bytes // 4
            else:
                tkinter.messagebox.showerror("Error:", message="Block size must be multiple of 4 bytes.")
                return

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

        if mode in ["CFB", "OFB", "CTR"]:
            iv_size = block_size_bytes
        elif mode == "CBC":
            if block_size_bytes % 8 == 0:
                iv_size = block_size_bytes
            else:
                iv_size = ((block_size_bytes // 8) + 1) * 8

        key_length = len(key)
        if key_length != key_size:
            tkinter.messagebox.showerror("Error:", message="Key size must be %d bytes." % key_size)
            return

        if mode in ["CBC", "CFB", "OFB", "CTR"] and len(iv) != iv_size:
            tkinter.messagebox.showerror("Error:", message="IV size must be %d bytes." % iv_size)
            return

        if endianness == "big":
            swap = True
        else:
            swap = False

        try:
            if mode in ["CFB", "OFB", "CTR"]:
                cipher = refinery.units.crypto.cipher.xxtea.xxtea(key=key, iv=iv, mode=mode, swap=swap, block_size=block_size)
            elif mode == "CBC":
                cipher = refinery.units.crypto.cipher.xxtea.xxtea(key=key, iv=iv, padding="pkcs7", mode=mode, swap=swap, block_size=block_size)
            elif mode == "ECB":
                cipher = refinery.units.crypto.cipher.xxtea.xxtea(key=key, padding="pkcs7", mode=mode, swap=swap, block_size=block_size)

            ciphertext = cipher.reverse(data=self.data)
        except Exception as e:
            tkinter.messagebox.showerror("Error:", message=e)
            self.root.quit()
            exit(1) # Not decrypted

        sys.stdout.buffer.write(ciphertext)
        self.root.quit()
        exit(0) # Encrypted successfully

if __name__ == "__main__":
    # Receive data
    data = sys.stdin.buffer.read()

    dialog = XXTEAEncryptDialog(title="XXTEA encrypt", data=data, use_single_block=True)
    dialog.show()
    exit(1) # Not decrypted
