FileInsight-plugins: McAfee FileInsight バイナリエディタ用のプラグイン

これらのプラグインは、マルウェア解析に関する様々なデコード作業に便利です。
（例：文書ファイル型のマルウェアからマルウェアの実行ファイルやダミーの文書
ファイルを抽出する）

インストール方法:
プラグインのフォルダを %USERPROFILE%\Documents\FileInsight\plugins にコピー
してください。FileInsight に加えて Python 2.7 (x86) をインストールしておく
必要があります。

※※※ お知らせ ※※※
残念なことに FileInsight は McAfee 社の Free Tools のウェブサイトから削除されました。
しかしながら、FileInsight のインストーラは以下の場所から引き続きダウンロード可能です。
https://www.mcafee.com/enterprise/en-us/downloads/free-tools/terms-of-use.html?url=http://downloadcenter.mcafee.com/products/mcafee-avert/fileinsight.zip

使用するために必要なもの:
aPLib compress と aPLib decompress のプラグインについては、aplib.dll が必要です。
aPLib を http://ibsensoftware.com/download.html からダウンロードして、
aplib.dll (32ビット版) を "Compression operations" のフォルダに置いてください。

ARC4 decrypt プラグインについては、PyCryptodome Python モジュールが必要です。
https://github.com/Legrandin/pycryptodome からダウンロード、インストールするか、
"c:\Python27\python.exe -m pip install pycryptodomex" を実行してインストールしてください。

File type plugin プラグインについては、python-magic Python モジュールが必要です。
https://github.com/ahupp/python-magic からダウンロード、インストールするか、
"c:\Python27\python.exe -m pip install python-magic-bin" を実行してインストール
してください。

Find PE file プラグインについては、pefile Python モジュールが必要です。
https://code.google.com/p/pefile/ からダウンロード、インストールするか、
"c:\Python27\python.exe -m pip install pefile" を実行してインストールして
ください。

YARA scan プラグインについては、yara-python Python モジュールが必要です。
https://github.com/VirusTotal/yara-python からダウンロード、インストールするか、
"c:\Python27\python.exe -m pip install yara-python" を実行してインストールして
ください。

以下のコマンドで全ての必要な Python モジュールをインストールできます。
c:\Python27\python.exe -m pip install -r requirements.txt

カスタマイズ:
Send to プラグインについては、あなたのお好みのプログラムを呼び出せるように
"Misc operations\send_to.json" を編集してください。

プラグインの一覧 (55個):
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
  * LZNT1 compress
    選択範囲を LZNT1 アルゴリズムで圧縮します。
  * LZNT1 decompress
    選択範囲を LZNT1 アルゴリズムで展開します。
  * Raw deflate
    選択範囲をヘッダとチェックサムを付けずに Deflate アルゴリズムで圧縮します。
    (PHP言語の gzdeflate() と同等)
  * Raw inflate
    ヘッダとチェックサムを付けずに Deflate 圧縮された選択範囲を展開します。
    (PHP言語の gzinflate() と同等)

* Crypto operations
  * AES decrypt
    選択範囲を AES で復号します。
  * AES encrypt
    選択範囲を AES で暗号化します。
  * ARC4 decrypt
    選択範囲を ARC4 (Alleged RC4) で復号します。
  * Blowfish decrypt
    選択範囲を Blowfish で復号します。
  * Blowfish dncrypt
    選択範囲を Blowfish で暗号化します。
  * DES decrypt
    選択範囲を DES で復号します。
  * DES dncrypt
    選択範囲を DES で暗号化します。
  * Triple DES decrypt
    選択範囲を Triple DES で復号します。
  * Triple DES dncrypt
    選択範囲を Triple DES で暗号化します。

* Encoding operations
  * Binary to hex text
    選択範囲のバイナリデータを16進数のテキストに変換します。
  * Hex text to binary
    選択範囲の16進数のテキストをバイナリデータに変換します。
  * Custom base64 decode
    選択範囲をカスタムbase64テーブルを使ってデコードします。
  * Custom base64 encode
    選択範囲をカスタムbase64テーブルを使ってエンコードします。
  * ROT13
    選択範囲を ROT13 アルゴリズムでデコードします。
  * From quoted printable
    選択範囲を quoted printable としてデコードします。
  * To quoted printable
    選択範囲を quoted printable としてエンコードします。

* Misc operations
  * Byte frequency
    選択範囲の(選択していない場合は全体の)値の出現頻度を出力します。
  * File comparison
    2つのファイルの内容を比較します。
  * File type
    選択範囲の(選択していない場合は全体の)ファイルの種類を判別します。
  * Hash values
    選択範囲の(選択していない場合は全体の) MD5, SHA1, SHA256 ハッシュ値を
    計算します。
  * Send to
    選択範囲を(選択していない場合は全体を)別のプログラムで開きます。

* Search operations
  * Find PE file
    選択範囲から(選択していない場合は全体から) PE ファイルを検索します。
  * Regex search
    選択範囲から(選択していない場合は全体から) 正規表現で検索します。
  * Replace
    選択範囲から(選択していない場合は全体から) 検索してマッチした領域を
    指定したデータで置換します。
    (the whole file if not selected)
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
    値の出現頻度に基づいて選択範囲から(選択していない場合は全体から) 256バイトの
    長さの XOR キーを推測します。
  * Visual encrypt
    選択範囲をマルウェアの Zeus で使われている visual encrypt アルゴリズムで
    エンコードします。
  * Visual decrypt
    選択範囲をマルウェアの Zeus で使われている visual decrypt アルゴリズムで
    デコードします。

作者: 萬谷 暢崇 (Email: nobutaka@nobutaka.org, Twitter: nmantani)
ライセンス: The BSD 2-Clause License (http://opensource.org/licenses/bsd-license.php)
