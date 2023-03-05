#
# Crypto operations - Various cryptographic operations
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

import subprocess

def aes_decrypt(fi):
    """
    Decrypt selected region with AES
    """
    do_decrypt(fi, "AES", "aes_decrypt_dialog.py")

def aes_encrypt(fi):
    """
    Encrypt selected region with AES
    """
    do_encrypt(fi, "AES", "aes_encrypt_dialog.py")

def rc2_decrypt(fi):
    """
    Decrypt selected region with RC2
    """
    do_decrypt(fi, "RC2", "rc2_decrypt_dialog.py")

def rc2_encrypt(fi):
    """
    Encrypt selected region with RC2
    """
    do_encrypt(fi, "RC2", "rc2_encrypt_dialog.py")

def rc4_decrypt(fi):
    """
    Decrypt selected region with RC4
    """
    do_decrypt(fi, "RC4", "rc4_decrypt_dialog.py")

def rc4_encrypt(fi):
    """
    Encrypt selected region with RC4
    """
    do_encrypt(fi, "RC4", "rc4_decrypt_dialog.py")

def blowfish_decrypt(fi):
    """
    Decrypt selected region with Blowfish
    """
    do_decrypt(fi, "Blowfish", "blowfish_decrypt_dialog.py")

def blowfish_encrypt(fi):
    """
    Encrypt selected region with Blowfish
    """
    do_encrypt(fi, "Blowfish", "blowfish_encrypt_dialog.py")

def chacha20_decrypt(fi):
    """
    Decrypt selected region with ChaCha20
    """
    do_decrypt(fi, "ChaCha20", "chacha20_decrypt_dialog.py")

def chacha20_encrypt(fi):
    """
    Encrypt selected region with ChaCha20
    """
    do_encrypt(fi, "ChaCha20", "chacha20_decrypt_dialog.py")

def des_decrypt(fi):
    """
    Decrypt selected region with DES
    """
    do_decrypt(fi, "DES", "des_decrypt_dialog.py")

def des_encrypt(fi):
    """
    Encrypt selected region with DES
    """
    do_encrypt(fi, "DES", "des_encrypt_dialog.py")

def salsa20_decrypt(fi):
    """
    Decrypt selected region with Salsa20
    """
    do_decrypt(fi, "Salsa20", "salsa20_decrypt_dialog.py")

def salsa20_encrypt(fi):
    """
    Encrypt selected region with Salsa20
    """
    do_encrypt(fi, "Salsa20", "salsa20_decrypt_dialog.py")

def tea_decrypt(fi):
    """
    Decrypt selected region with TEA (Tiny Encryption Algorithm)
    """
    do_decrypt(fi, "TEA", "tea_decrypt_dialog.py")

def tea_encrypt(fi):
    """
    Encrypt selected region with TEA (Tiny Encryption Algorithm)
    """
    do_encrypt(fi, "TEA", "tea_encrypt_dialog.py")

def triple_des_decrypt(fi):
    """
    Decrypt selected region with Triple DES
    """
    do_decrypt(fi, "Triple DES", "triple_des_decrypt_dialog.py")

def triple_des_encrypt(fi):
    """
    Encrypt selected region with Triple DES
    """
    do_encrypt(fi, "Triple DES", "triple_des_encrypt_dialog.py")

def xtea_decrypt(fi):
    """
    Decrypt selected region with Triple DES
    """
    do_decrypt(fi, "XTEA", "xtea_decrypt_dialog.py")

def xtea_encrypt(fi):
    """
    Encrypt selected region with Triple DES
    """
    do_encrypt(fi, "XTEA", "xtea_encrypt_dialog.py")

def rc5_decrypt(fi):
    """
    Decrypt selected region with RC5
    """
    do_decrypt(fi, "RC5", "rc5_decrypt_dialog.py")

def rc5_encrypt(fi):
    """
    Encrypt selected region with RC5
    """
    do_encrypt(fi, "RC5", "rc5_encrypt_dialog.py")

def do_decrypt(fi, name, script):
    """
    Decrypt selected region
    """

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute xxxx_decrypt_dialog.py to show GUI
        # GUI portion is moved to external script to avoid hangup of FileInsight
        script = "Crypto/" + script
        p = subprocess.Popen([fi.get_embed_python(), script], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive decrypted data
        stdout_data, stderr_data = p.communicate(data)
        ret = p.wait()

        if ret == -1: # PyCryptodome is not installed
            fi.show_module_install_instruction("Cryptodome", "pycryptodomex")
            return
        if ret == -2: # PyTEA is not installed
            fi.show_module_install_instruction("pytea", "PyTEA")
            return
        if ret == -3: # xtea is not installed
            fi.show_module_install_instruction("xtea")
            return
        if ret == -4: # Binary Refinery is not installed
            fi.show_module_install_instruction("refinery", "binary-refinery")
            return
        elif ret == 1: # Do nothing if not decrypted
            return

        decrypted_data = stdout_data
        decrypted_len = len(decrypted_data)
        newdata = orig[:offset] + decrypted_data + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of %s decrypt" % name)
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, decrypted_len, hex(offset), "#c8ffff")

        if length == 1:
            print("Decrypted one byte with %s from offset %s to %s." % (name, hex(offset), hex(offset)))
        else:
            print("Decrypted %s bytes with %s from offset %s to %s." % (length, name, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to decrypted region.")
    else:
        print("Please select a region to use this plugin.")

def do_encrypt(fi, name, script):
    """
    Encrypt selected region
    """

    offset = fi.getSelectionOffset()
    length = fi.getSelectionLength()

    if length > 0:
        data = fi.getSelection()
        orig = fi.getDocument()
        orig_len = len(orig)

        # Do not show command prompt window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # Execute xxxx_decrypt_dialog.py to show GUI
        # GUI portion is moved to external script to avoid hangup of FileInsight
        script = "Crypto/" + script
        p = subprocess.Popen([fi.get_embed_python(), script], startupinfo=startupinfo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Receive decrypted data
        stdout_data, stderr_data = p.communicate(data)
        ret = p.wait()

        if ret == -1: # PyCryptodome is not installed
            fi.show_module_install_instruction("Cryptodome", "pycryptodomex")
            return
        if ret == -2: # PyTEA is not installed
            fi.show_module_install_instruction("pytea", "PyTEA")
            return
        if ret == -3: # xtea is not installed
            fi.show_module_install_instruction("xtea")
            return
        if ret == -4: # Binary Refinery is not installed
            fi.show_module_install_instruction("refinery", "binary-refinery")
            return
        elif ret == 1: # Do nothing if not decrypted
            return

        encrypted_data = stdout_data
        encrypted_len = len(encrypted_data)
        newdata = orig[:offset] + encrypted_data + orig[offset + length:]

        tab_name = fi.get_new_document_name("Output of %s encrypt" % name)
        fi.newDocument(tab_name, 1)
        fi.setDocument(newdata)
        fi.setBookmark(offset, encrypted_len, hex(offset), "#c8ffff")

        if length == 1:
            print("Encrypted one byte with %s from offset %s to %s." % (name, hex(offset), hex(offset)))
        else:
            print("Encrypted %s bytes with %s from offset %s to %s." % (length, name, hex(offset), hex(offset + length - 1)))
        print("Added a bookmark to encrypted region.")
    else:
        print("Please select a region to use this plugin.")
