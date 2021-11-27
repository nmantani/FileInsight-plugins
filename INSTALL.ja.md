# インストール方法
## 自動でのインストール
以下のコマンドを実行してください。FileInsight-plugins と FileInsight を含む全ての必要なものがインストールされます。

```
powershell -exec bypass -command "IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))"
```

プロキシサーバを使用している場合は (例えば IPアドレス: 10.0.0.1 ポート番号: 8080) 以下のコマンドを実行してください。

```
curl -x http://10.0.0.1:8080 -Lo install.ps1 https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1
powershell -exec bypass .\install.ps1
```

## 手動でのインストール
手動でのインストールは多数の手順が必要となりますので、**自動でのインストールを強くおすすめします。**

### **FileInsight のインストール**
FileInsight のインストーラは McAfee Free Tools のウェブサイトから入手可能です。こちらからダウンロードしてください。
https://www.mcafee.com/enterprise/en-us/downloads/free-tools/fileInsight.html

### **Python 3のインストール**
FileInsight のビルトインの Python インタプリタは Python 2 ですが、FileInsight-plugins は 2.0 以降 Python 3 (x64) が必要です（過去のバージョンでは Python 2 (x86) が必要でした）。 最新バージョン (3.5) の FileInsight ではもう Python 2 (x86) をインストールする必要はありません。Python 3 (x64) のインストーラはこちらからダウンロードしてください。
https://www.python.org/downloads/windows/  
現在 Python 3.10.x で使用できない Python モジュールがいくつかあります (ppmd-cffi や yara-python) ので Python 3.9.x の使用をお勧めします。

### **FileInsight-pluginsのインストール**
plugins フォルダを %USERPROFILE%\Documents\McAfee FileInsight
にコピーしてください。FileInsight に加えて Python 3 (x64) をインストールしておく必要があります。

![folders.png](docs/folders.png)

### **使用するために必要なもの**
aPLib compress と aPLib decompress のプラグインについては、aplib.dll が必要です。
aPLib を http://ibsensoftware.com/download.html からダウンロードして、
aplib.dll (32ビット版) を "plugins\Operations\Compression" のフォルダに置いてください。

QuickLZ compress と QuickLZ decompress のプラグインについては、QuickLZ の DLL ファイルが必要です。
QuickLZ の DLL ファイル を http://www.quicklz.com/150dll.zip からダウンロードして、
quicklz150_64_1_safe.dll、quicklz150_64_2_safe.dll、quicklz150_64_3_safe.dll (64 ビット版) を
"plugins\Operations\Compression" のフォルダに置いてください。

Binwalk scan プラグインについては、 binwalk Python モジュールが必要です。
https://github.com/ReFirmLabs/binwalk からダウンロード、インストールしてください
(binwalk のインストールに pip は使用できません)。

以下に書かれている Python モジュールのうちいくつかは以下のコマンドでまとめてインストールできます。
```
py.exe -3 -m pip install -r requirements.txt
```

AES decrypt 等の暗号関係のプラグインについては、PyCryptodome Python モジュールが必要です。
https://github.com/Legrandin/pycryptodome からダウンロード、インストールするか、
```
py.exe -3 -m pip install pycryptodomex
```
を実行してインストールしてください。

File type プラグインについては、python-magic Python モジュールが必要です。
https://github.com/ahupp/python-magic からダウンロード、インストールするか、
```
py.exe -3 -m pip install python-magic-bin
```
を実行してインストールしてください。

Find PE file プラグインについては、pefile Python モジュールが必要です。
https://github.com/erocarrera/pefile からダウンロード、インストールするか、
```
py.exe -3 -m pip install pefile
```
を実行してインストールしてください。

YARA scan プラグインについては、yara-python Python モジュールが必要です。
https://github.com/VirusTotal/yara-python からダウンロード、インストールするか、
```
py.exe -3 -m pip install yara-python
```
を実行してインストールしてください。

Emulate code プラグインについては、Qiling Framework と watchdog Python モジュールが必要です。
https://github.com/qilingframework/qiling/ と https://github.com/gorakhargosh/watchdog から
ダウンロード、インストールするか、以下のコマンドを実行してインストールしてください。
```
py.exe -3 -m pip install qiling
py.exe -3 -m pip install watchdog
```

また、Qiling Framework の rootfs ファイルをセットアップする
必要があります。https://github.com/qilingframework/qiling/archive/master.zip
をダウンロードして、展開された qiling-master フォルダを
"plugins\Operations\Misc" フォルダにコピーしてください。

それから https://github.com/qilingframework/rootfs/archive/master.zip を
ダウンロードして、展開された rootfs-master フォルダ以下にある arm_linux 等のフォルダを "plugins\Operations\Misc\qiling-master\examples\rootfs" にコピーしてください。

それらの後で PowerShell で以下のコマンドを実行して、rootfs の
DLL ファイルとレジストリのセットアップを行ってください。

```powershell
$dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc"

Start-Process powershell -Verb RunAs -Wait -ArgumentList "-Command `"cd '${dest_dir}\qiling-master'; examples\scripts\dllscollector.bat`""
```

Disassemble プラグインについては、Capstone が必要です。
https://github.com/capstone-engine/capstone/ からダウンロード、インストールするか、
```
py.exe -3 -m pip install capstone
```
を実行してインストールしてください。

Hash values プラグインについては、pyimpfuzzy-windows が必要です。
https://github.com/JPCERTCC/impfuzzy/ からダウンロード、インストールするか、
```
py.exe -3 -m pip install pyimpfuzzy-windows
```
を実行してインストールしてください。

LZ4 compress と LZ4 decompress のプラグインについては、python-lz4 が必要です。
https://github.com/python-lz4/python-lz4/ からダウンロード、インストールするか、
```
py.exe -3 -m pip install lz4
```
を実行してインストールしてください。

Zstandard compress と Zstandard decompress のプラグインについては、python-zstandard が必要です。
https://github.com/indygreg/python-zstandard/ からダウンロード、インストールするか、
```
py.exe -3 -m pip install zstandard
```
を実行してインストールしてください。

Protobuf decode プラグインについては、blackboxprotobuf (フォークしたバージョン) が必要です。
https://github.com/ydkhatri/blackboxprotobuf/ からダウンロード、インストールするか、
```
py.exe -3 -m pip install blackboxprotobuf
```
を実行してインストールしてください。

LZO compress と LZO decompress のプラグインについては、python-lzo が必要です。
https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-lzo からお使いの Python の
バージョン用の wheel ファイル (.whl) をダウンロードして、以下のコマンドを実行して
インストールしてください。
```
py.exe -3 -m pip install python_lzo-x.xx-cpxx-cpxx-win_amd64.whl
```

PPMd compress と PPMd decompress のプラグインについては、ppmd-cffi が必要です。
https://github.com/miurahr/ppmd からダウンロード、インストールするか、
```
py.exe -3 -m pip install ppmd-cffi
```
を実行してインストールしてください。

Bitmap view プラグインについては、Pillow が必要です。
https://github.com/python-pillow/Pillow からダウンロード、インストールするか、
```
py.exe -3 -m pip install Pillow
```
を実行してインストールしてください。

TEA decrypt と TEA encrypt のプラグインについては、PyTEA が必要です。
https://github.com/codeif/PyTEA からダウンロード、インストールするか、
```
py.exe -3 -m pip install PyTEA
```
を実行してインストールしてください。

XTEA decrypt と XTEA encrypt のプラグインについては、xtea が必要です。
https://github.com/Varbin/xtea からダウンロード、インストールするか、
```
py.exe -3 -m pip install xtea
```
を実行してインストールしてください。

Byte histogram と Entropy graph のプラグインについては、seaborn が必要です。
https://github.com/mwaskom/seaborn からダウンロード、インストールするか、
```
py.exe -3 -m pip install seaborn
```
を実行してインストールしてください。

Byte histogram と Entropy graph のプラグインについては、matplotlib が必要です。
https://github.com/matplotlib/matplotlib/ からダウンロード、インストールするか、
```
py.exe -3 -m pip install matplotlib
```
を実行してインストールしてください。

Check for update メニューで FileInsight-plugins の更新版のチェックを行うにはrequests が必要です。
https://github.com/psf/requests/ からダウンロード、インストールするか、
```
py.exe -3 -m pip install requests
```
を実行してインストールしてください。

LZF compress と LZF decompress のプラグインについては、python-lzf が必要です。
https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-lzf からお使いの Python の
バージョン用の wheel ファイル (.whl) をダウンロードして、以下のコマンドを実行して
インストールしてください。
```
py.exe -3 -m pip install python_lzf-x.x.x-cpxx-cpxx-win_amd64.whl
```

LZJB compress と LZJB decompress のプラグインについては、python-lzjb が必要です。
https://github.com/unwind/python-lzjb からダウンロード、インストールするか、
```
py.exe -3 -m pip install https://github.com/unwind/python-lzjb/archive/refs/heads/master.zip
```
を実行してインストールしてください。

Show metadata プラグインについては、ExifTool が必要です。
https://exiftool.org/ から ExifTool をダウンロードして、exiftool(-k).exe　を
exiftool.exe という名前で "plugins\Operations\Parsing" フォルダにコピーしてください。
