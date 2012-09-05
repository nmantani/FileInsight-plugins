Tiny plugins for McAfee FileInsight

List of plugins:

* Copy to new file
  Copy selected region (the whole file if not selected) to new file

* Decremental XOR
  XOR selected region while decrementing XOR key

* Hash values
  Calculate MD5, SHA1, SHA256 hash values of selected region (the whole
  file if not selected)

* Incremental XOR
  XORing selected region while incrementing XOR key

* Reverse order
  Reverse order of selected region

* Swap two bytes
  Swap each pair of bytes of selected region

* TrID
  Send selected region (the whole file if not selected) to TrID

* Null-preserving XOR
  XOR selected region while skipping data 0x00

How to use:
Please copy plugin folders to %USERPROFILE%\Documents\FileInsight\plugins .
For the TrID plugin, please edit TRID_PATH variable in main.py according to your TrID installation path.

Author: Nobutaka Mantani <nobutaka@nobutaka.org>

