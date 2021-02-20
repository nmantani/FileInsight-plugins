# How to install
## Automatic installation
Please execute the following command. The latest release version of FileInsight-plugins and all pre-requisites including FileInsight will be installed.

```
powershell -exec bypass -command "IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))"
```

If you use a HTTP proxy, please download install.ps1 and edit $PROXY_HOST and $PROXY_PORT variables in it,
then please execute the following command.

```
powershell -exec bypass .\install.ps1
```

## Manual installation
**I strongly recommend automatic installation** because manual installation requires many steps.

### **Installation of FileInsight**
FileInsight installer is available at the McAfee Free Tools website.
Please get it from https://www.mcafee.com/enterprise/en-us/downloads/free-tools/fileInsight.html .

### **Installation of Python 3**
FileInsight-plugins requires Python 3 (x64) since version 2.0 (older versions require Python 2 (x86)), though the built-in Python interpreter of FileInsight is Python 2. You no longer need to install Python 2 (x86) with the latest version (3.5) of FileInsight. Please get Python 3 (x64) installer from https://www.python.org/downloads/windows/ .

### **Installation of FileInsight-plugins**
Please copy "plugins" folder into %USERPROFILE%\Documents\McAfee FileInsight .

![folders.png](docs/folders.png)

### **Pre-requisites**
For the "aPLib compress" and "aPLib decompress" plugins, they require aplib.dll.
Please download aPLib from http://ibsensoftware.com/download.html and copy
aplib.dll (32 bits version) into "plugins\Operations\Compression" folder.

For the "QuickLZ compress" and "QuickLZ decompress" plugins, they require QuickLZ DLL files.
Please download QuickLZ DLL files from http://www.quicklz.com/150dll.zip and copy
quicklz150_64_1_safe.dll, quicklz150_64_2_safe.dll and quicklz150_64_3_safe.dll (64 bits version)
into "plugins\Operations\Compression" folder.

For the "Binwalk scan" plugin, it requires binwalk Python module.
Please get it from https://github.com/ReFirmLabs/binwalk
(pip cannot be used to install binwalk)."

You can install some of required Python modules described below with the following command.
```
py.exe -3 -m pip install -r requirements.txt
```

For crypto-related plugins such as "AES decrypt", they require PyCryptodome Python module.
Please get it from https://github.com/Legrandin/pycryptodome
or execute the following command.
```
py.exe -3 -m pip install pycryptodomex
```

For the "File type" plugin, it requires python-magic Python module.
Please get it from https://github.com/ahupp/python-magic
or execute the following command.
```
py.exe -3 -m pip install python-magic-bin
```

For the "Find PE" file plugin, it requires pefile Python module.
Please get it from https://github.com/erocarrera/pefile
or execute the following command.
```
py.exe -3 -m pip install pefile
```

For the "YARA scan" plugin, it requires yara-python Python module.
Please get it from https://github.com/VirusTotal/yara-python
or execute the following command.
```
py.exe -3 -m pip install yara-python
```

For the "Emulate code" plugin, it requires Qiling Framework and watchdog Python module.
Please get it from https://github.com/qilingframework/qiling/ and
https://github.com/gorakhargosh/watchdog .
or execute the following commands.
```
py.exe -3 -m pip install qiling
py.exe -3 -m pip install watchdog
```

You also need to set up rootfs files of Qiling Framework.
Please download them from https://github.com/qilingframework/qiling/archive/master.zip and copy extracted "qiling-master" folder into "plugins\Operations\Misc" folder.

Then please setup DLL files and registry files of rootfs with the following commands on PowerShell:
```powershell
$dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc"

Start-Process powershell -Verb RunAs -Wait -ArgumentList "-Command `"cd '${dest_dir}\qiling-master'; examples\scripts\dllscollector.bat`""
```

For the "Disassemble" plugin, it requires Capstone.
Please get it from https://github.com/aquynh/capstone/
or execute the following command.
```
py.exe -3 -m pip install capstone
```

For the "Hash values" plugin, it requires pyimpfuzzy-windows.
Please get it from https://github.com/JPCERTCC/impfuzzy/
or execute the following command.
```
py.exe -3 -m pip install pyimpfuzzy-windows
```

For the "LZ4 compress" and "LZ4 decompress" plugins, they require python-lz4.
Please get it from https://github.com/python-lz4/python-lz4/
or execute the following command.
```
py.exe -3 -m pip install lz4
```

For the "Zstandard compress" and "Zstandard decompress" plugins, they require python-zstandard.
Please get it from https://github.com/indygreg/python-zstandard/
or execute the following command.
```
py.exe -3 -m pip install zstandard
```

For the "Protobuf decode" plugin, it requires blackboxprotobuf (forked version).
Please get it from https://github.com/ydkhatri/blackboxprotobuf/
or execute the following command.
```
py.exe -3 -m pip install blackboxprotobuf
```

For the "LZO compress" and "LZO decompress" plugins, they require python-lzo.
Please manually download python-lzo wheel file (.whl) for your Python version
from https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-lzo and install it
with the following command.
```
py.exe -3 -m pip install python_lzo-x.xx-cpxx-cpxx-win_amd64.whl
```

For the "PPMd compress" and "PPMd decompress" plugins, they require ppmd-cffi.
Please get it from https://github.com/miurahr/ppmd
or execute the following command.
```
py.exe -3 -m pip install ppmd-cffi
```

For the "Bitmap view" plugin, it requires Pillow.
Please get it from https://github.com/python-pillow/Pillow
or execute the following command.
```
py.exe -3 -m pip install Pillow
```

For the "TEA decrypt" and "TEA encrypt" plugins, it requires PyTEA.
Please get it from https://github.com/codeif/PyTEA
or execute the following command.
```
py.exe -3 -m pip install PyTEA
```

For the "XTEA decrypt" and "XTEA encrypt" plugins, it requires xtea.
Please get it from https://github.com/Varbin/xtea
or execute the following command.
```
py.exe -3 -m pip install xtea
```

For the "Show metadata" plugin, it requires ExifTool.
Please download ExifTool from https://exiftool.org/
and copy exiftool(-k).exe as exiftool.exe into "plugins\Operations\Parsing" folder.
