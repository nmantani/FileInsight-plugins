Tiny plugins for McAfee FileInsight

These plugins may be useful for extracing malware executables and
decoy documents from malicious document files.

List of plugins:

* Binary to hex text
  Convert binary of selected region into hex text

* Byte frequency
  Show byte frequency of selected region (the whole file if not selected)

* Copy to new file
  Copy selected region (the whole file if not selected) to new file

* Decremental XOR
  XOR selected region while decrementing XOR key

* Fill
  Fill selected region with specified hex pattern

* Hash values
  Calculate MD5, SHA1, SHA256 hash values of selected region (the whole
  file if not selected)

* Hex text to binary
  Convert hex text of selected region into binary

* Incremental XOR
  XOR selected region while incrementing XOR key

* Null-preserving XOR
  XOR selected region while skipping null bytes

* Reverse order
  Reverse order of selected region

* Swap nibbles
  Swap each pair of nibbles of selected region

* Swap two bytes
  Swap each pair of bytes of selected region

* TrID
  Send selected region (the whole file if not selected) to TrID

* XOR hex search
  Search XORed / bit-rotated data in selected region (the whole file
  if not selected)

* XOR text search
  Search XORed / bit-rotated string in selected region (the whole file
  if not selected)

* XOR with next byte
  XOR selected region while using next byte as XOR key

How to use:
Please copy plugin folders to %USERPROFILE%\Documents\FileInsight\plugins .
You need Python installed in addition to FileInsight.

For the TrID plugin, please edit TRID_PATH variable in main.py according to
your TrID installation path.

Author: Nobutaka Mantani (Email: nobutaka@nobutaka.org, Twitter: nmantani)
License: The BSD 2-Clause License (http://opensource.org/licenses/bsd-license.php)

