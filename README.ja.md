# FileInsight-plugins: McAfee FileInsight バイナリエディタのマルウェア解析用デコードツールボックス

FileInsight-plugins は McAfee FileInsight バイナリエディタ用のプラグイン集です。
暗号の復号、圧縮の展開、XOR された文字列の検索、YARA ルールでのスキャン等、多数の機能を追加できます。
マルウェア解析に関する様々なデコード作業に便利です。（例：文書ファイル型のマルウェアからマルウェアの実行ファイルやダミーの文書ファイルを抽出する）

## スクリーンショット
![screenshot1.png](docs/screenshot1.png)

![screenshot2.png](docs/screenshot2.png)

## インストール方法
### 自動でのインストール
以下のコマンドを実行してください。FileInsight-plugins と全ての必要なものがインストールされます。

powershell -exec bypass -command "IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))"

HTTP プロキシをお使いの場合は install.ps1 をダウンロードして、ファイル中の $PROXY_HOST と
$PROXY_PORT の変数を編集してから以下のコマンドを実行してください。

powershell -exec bypass .\install.ps1

### 手動でのインストール
plugins フォルダを %USERPROFILE%\Documents\FileInsight
にコピーしてください。FileInsight に加えて Python 2.7 (x86) をインストールしておく必要があります。

![folders.png](docs/folders.png)

FileInsight は Python 3 と互換性が無いためプラグインを Python 3 で使用することはできません。
**もし他のツール等で Python 3 を使用したい場合は Python 2.7 を "Install just for me"
でインストールしてください。** Python 2.7 を "Install for all users" でインストールすると
FileInsight が Python 2.7 ではなく Python 3 を使用しようとしてプラグインを実行できなくなります。
また、Python 2.7 の python.exe が FileInsight から確実に実行されるように以下のコマンドを管理者
権限で実行してください。

mklink "C:\Program Files (x86)\FileInsight\python.exe" C:\Python27\python.exe

### **FileInsight のインストーラについて**
FileInsight は McAfee 社の Free Tools のウェブサイトから削除されました。
しかしながら、FileInsight のインストーラは以下の場所から引き続きダウンロード可能です。
https://www.mcafee.com/enterprise/en-us/downloads/free-tools/terms-of-use.html?url=http://downloadcenter.mcafee.com/products/mcafee-avert/fileinsight.zip

## 使用するために必要なもの
aPLib compress と aPLib decompress のプラグインについては、aplib.dll が必要です。
aPLib を http://ibsensoftware.com/download.html からダウンロードして、
aplib.dll (32ビット版) を "Compression operations" のフォルダに置いてください。

Binwalk scan プラグインについては、 binwalk Python モジュールが必要です。
https://github.com/ReFirmLabs/binwalk からダウンロード、インストールしてください
(binwalk のインストールに pip は使用できません)。

AES decrypt 等の暗号関係のプラグインについては、PyCryptodome Python モジュールが必要です。
https://github.com/Legrandin/pycryptodome からダウンロード、インストールするか、
"C:\Python27\python.exe -m pip install pycryptodomex" を実行してインストールしてください。

LZMA Compress 等の LZMA 関係のプラグインについては、backports.lzma Python モジュールが必要です。
https://github.com/peterjc/backports.lzma からダウンロード、インストールするか、
"C:\Python27\python.exe -m pip install -i https://pypi.anaconda.org/nehaljwani/simple backports.lzma"
を実行してインストールしてください。

File type プラグインについては、python-magic Python モジュールが必要です。
https://github.com/ahupp/python-magic からダウンロード、インストールするか、
"C:\Python27\python.exe -m pip install python-magic-bin" を実行してインストール
してください。

Find PE file プラグインについては、pefile Python モジュールが必要です。
https://github.com/erocarrera/pefile からダウンロード、インストールするか、
"C:\Python27\python.exe -m pip install pefile" を実行してインストールして
ください。

YARA scan プラグインについては、yara-python Python モジュールが必要です。
https://github.com/VirusTotal/yara-python からダウンロード、インストールするか、
"C:\Python27\python.exe -m pip install yara-python" を実行してインストールして
ください。

以下のコマンドで必要な Python モジュールのうちいくつかをまとめてインストールできます。
C:\Python27\python.exe -m pip install -r requirements.txt

## カスタマイズ
Send to プラグインについては、あなたのお好みのプログラムを呼び出せるように
"Misc operations\send_to.json" を編集してください。

## 使い方
Plugins タブにあるカテゴリをクリックしてプラグインを選択してください。

![how_to_use1.png](docs/how_to_use1.png)

右クリックのメニューからプラグインを使用することもできます。

![how_to_use2.png](docs/how_to_use2.png)

いくつかのプラグインは使用時に設定のダイアログを表示します。

![how_to_use3.png](docs/how_to_use3.png)

## プラグインの一覧 (67個)
* Basic operations
  * Copy to new file  
    選択範囲を(選択していない場合は全体を)新しいファイルとして開きます。
  * Delete before  
    現在のカーソル位置より前を全て削除します。
  * Delete after  
    現在のカーソル位置より後を全て削除します。
  * Fill  
    選択範囲を指定した16進数のパターンで埋めます。
  * Invert  
    選択範囲のビットを反転します。
  * Reverse order  
    選択範囲のバイト列の順序を逆に並べ替えます。
  * Swap nibbles  
    選択範囲内のニブルの組を入れ替えます。
  * Swap two bytes  
    選択範囲内のバイトの組を入れ替えます。
  * To upper case  
    選択範囲内の小文字を大文字にします。
  * To lower case  
    選択範囲内の大文字を小文字にします。
  * Swap case  
    選択範囲内の大文字と小文字を入れ替えます。

* Compression operations
  * aPLib compress  
    選択範囲を aPLib 圧縮ライブラリで圧縮します。
  * aPLib decompress  
    選択範囲を aPLib 圧縮ライブラリで展開します。
  * Bzip2 compress  
    選択範囲を bzip2 アルゴリズムで圧縮します。
  * Bzip2 decompress  
    選択範囲を bzip2 アルゴリズムで展開します。
  * Gzip compress  
    選択範囲を gzip 形式で圧縮します。
  * Gzip decompress  
    gzip 形式で圧縮された選択範囲を展開します。
  * LZMA compress  
    選択範囲を LZMA アルゴリズムで圧縮します。
  * LZMA decompress  
    選択範囲を LZMA アルゴリズムで展開します。
  * LZNT1 compress  
    選択範囲を LZNT1 アルゴリズムで圧縮します。
  * LZNT1 decompress  
    選択範囲を LZNT1 アルゴリズムで展開します。
  * Raw deflate  
    選択範囲をヘッダとチェックサムを付けずに Deflate アルゴリズムで圧縮します。(PHP言語の gzdeflate() と同等)
  * Raw inflate  
    ヘッダとチェックサムを付けずに Deflate 圧縮された選択範囲を展開します。(PHP言語の gzinflate() と同等)
  * XZ compress  
    選択範囲を XZ 形式で圧縮します。
  * XZ decompress  
    選択範囲を XZ 形式として展開します。

* Crypto operations
  * AES decrypt  
    選択範囲を AES で復号します。
  * AES encrypt  
    選択範囲を AES で暗号化します。
  * ARC2 decrypt  
    選択範囲を ARC2 (Alleged RC2) で復号します。
  * ARC2 encrypt  
    選択範囲を ARC2 (Alleged RC2) で暗号化します。
  * ARC4 decrypt / encrypt  
    選択範囲を ARC4 (Alleged RC4) で復号 / 暗号化します。
  * Blowfish decrypt  
    選択範囲を Blowfish で復号します。
  * Blowfish encrypt  
    選択範囲を Blowfish で暗号化します。
  * ChaCha20 decrypt / encrypt  
    選択範囲を ChaCha20 で復号 / 暗号化します。
  * DES decrypt  
    選択範囲を DES で復号します。
  * DES encrypt  
    選択範囲を DES で暗号化します。
  * Salsa20 decrypt / encrypt  
    選択範囲を Salsa20 で復号 / 暗号化します。
  * Triple DES decrypt  
    選択範囲を Triple DES で復号します。
  * Triple DES encrypt  
    選択範囲を Triple DES で暗号化します。

* Encoding operations
  * Binary data to hex text  
    選択範囲のバイナリデータを16進数のテキストに変換します。
  * Hex text to binary data  
    選択範囲の16進数のテキストをバイナリデータに変換します。
  * Binary data to binary text  
    選択範囲のバイナリデータを2進数のテキストに変換します。
  * Binary text to binary data  
    選択範囲の2進数のテキストをバイナリデータに変換します。
  * Custom base64 decode  
    選択範囲をカスタムbase64テーブルを使ってデコードします。
  * Custom base64 encode  
    選択範囲をカスタムbase64テーブルを使ってエンコードします。
  * ROT13  
    選択範囲のアルファベットの文字列を指定した数だけローテートします。(デフォルト: 13)
  * From quoted printable  
    選択範囲を quoted printable としてデコードします。
  * To quoted printable  
    選択範囲を quoted printable としてエンコードします。

* Misc operations
  * Byte frequency  
    選択範囲の(選択していない場合は全体の)値の出現頻度を出力します。
  * File comparison  
    2つのファイルの内容を比較します。
  * Hash values  
    選択範囲の(選択していない場合は全体の) MD5, SHA1, SHA256 ハッシュ値を計算します。
  * Send to  
    選択範囲を(選択していない場合は全体を)別のプログラムで開きます。

* Parsing operations
  * Binwalk scan  
    選択範囲を(選択していない場合は全体を)スキャンして埋め込まれたファイルを探します。
  * File type  
    選択範囲の(選択していない場合は全体の)ファイルの種類を判別します。
  * Find PE file  
    選択範囲から(選択していない場合は全体から) PE ファイルを検索します。
  * Strings  
    選択範囲から(選択していない場合は全体から)文字列を抽出します。

* Search operations
  * Regex search  
    選択範囲から(選択していない場合は全体から) 正規表現で検索します。
  * Replace  
    選択範囲から(選択していない場合は全体から) 検索してマッチした領域を指定したデータで置換します。
  * XOR hex search  
    選択範囲から(選択していない場合は全体から) XOR またはビットローテートされて
    いるバイト列を検索します。
  * XOR text search  
    選択範囲から(選択していない場合は全体から) XOR またはビットローテートされて
    いる文字列を検索します。
  * YARA scan  
    選択範囲を(選択していない場合は全体を) YARA でスキャンします。

* XOR operations
  * Decremental XOR  
    選択範囲を XOR キーの値を減らしながら XOR します。
  * Incremental XOR  
    選択範囲を XOR キーの値を増やしながら XOR します。
  * Null-preserving XOR  
    選択範囲をヌルバイトと XOR キー自体をスキップしながら XOR します。
  * XOR with next byte  
    選択範囲を次のバイトを XOR のキーにしながら XOR します。
  * Guess 256 byte XOR keys  
    値の出現頻度に基づいて選択範囲から(選択していない場合は全体から)256バイトの長さの XOR キーを推測します。
  * Visual encrypt  
    選択範囲をマルウェアの Zeus で使われている visual encrypt アルゴリズムでエンコードします。
  * Visual decrypt  
    選択範囲をマルウェアの Zeus で使われている visual decrypt アルゴリズムでデコードします。

## 作者
萬谷 暢崇 (Twitter: @nmantani)

## ライセンス
The BSD 2-Clause License (http://opensource.org/licenses/bsd-license.php)
