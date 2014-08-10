Tiny plugins for McAfee FileInsight

These plugins would be useful for extracing malware executables and decoy
documents from malicious document files.

How to use:
Please copy plugin folders to %USERPROFILE%\Documents\FileInsight\plugins .
You need Python 2.7 (x86) installed in addition to FileInsight.

For the TrID plugin, please edit TRID_PATH variable in main.py according to
your TrID installation path.

For the Find PE file plugin, it requires pefile Python module.
Please get it from https://code.google.com/p/pefile/ .

For the "Send to" plugin, please edit launcher.py to run your favorite programs.

For the "ARC4 decrypt" plugin, it requires PyCrypto Python module.
Please get it from http://www.voidspace.org.uk/python/modules.shtml#pycrypto .

List of plugins:
* ARC4 decrypt
  Decrypt selected region with ARC4 (Alleged RC4)

* Binary to hex text
  Convert binary of selected region into hex text

* Byte frequency
  Show byte frequency of selected region (the whole file if not selected)

* Bzip2 compress
  Compress selected region with bzip2 algorithm

* Bzip2 decompress
  Decompress selected region with bzip2 algorithm

* Copy to new file
  Copy selected region (the whole file if not selected) to new file

* Decremental XOR
  XOR selected region while decrementing XOR key

* Delete after
  Delete all region after current cursor position

* Delete before
  Delete all region before current cursor position

* Fill
  Fill selected region with specified hex pattern

* Find PE file
  Find PE file from selected region (the whole file if not selected)

* Guess 256 byte XOR keys
  Guess 256 byte XOR keys from selected region (the whole file if not selected)
  based on the byte frequency

* Hash values
  Calculate MD5, SHA1, SHA256 hash values of selected region (the whole
  file if not selected)

* Hex text to binary
  Convert hex text of selected region into binary

* Incremental XOR
  XOR selected region while incrementing XOR key

* Invert
  Invert bits of selected region

* LZNT1 compress
  Compress selected region with LZNT1 algorithm

* LZNT1 decompress
  Decompress selected region with LZNT1 algorithm

* Null-preserving XOR
  XOR selected region while skipping null bytes and XOR key itself

* Reverse order
  Reverse order of selected region

* ROT13
  Decode selected region with ROT13 algorithm

* Send to
  Send selected region (the whole file if not selected) to other programs

* Swap nibbles
  Swap each pair of nibbles of selected region

* Swap two bytes
  Swap each pair of bytes of selected region

* TrID
  Send selected region (the whole file if not selected) to TrID

* Visual encrypt
  Encode selected region with visual encrypt algorithm

* Visual decrypt
  Decode selected region with visual decrypt algorithm

* XOR hex search
  Search XORed / bit-rotated data in selected region (the whole file
  if not selected)

* XOR text search
  Search XORed / bit-rotated string in selected region (the whole file
  if not selected)

* XOR with next byte
  XOR selected region while using next byte as XOR key

Author: Nobutaka Mantani (Email: nobutaka@nobutaka.org, Twitter: nmantani)
License: The BSD 2-Clause License (http://opensource.org/licenses/bsd-license.php)

