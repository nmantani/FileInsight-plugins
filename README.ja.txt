FileInsight-plugins: McAfee FileInsight バイナリエディタ用の小さなプラグイン

これらのプラグインは文書ファイル型のマルウェアからマルウェアの実行ファイルや
ダミーの文書ファイルを抽出するのに便利かもしれません。

使い方:
プラグインのフォルダを %USERPROFILE%\Documents\FileInsight\plugins にコピー
してください。FileInsight に加えて Python 2.7 (x86) をインストールしておく
必要があります。

TrID プラグインについては、TrID がインストールされている場所に合わせて
main.py の変数 TRID_PATH を編集してください。

Find PE file プラグインについては、pefile Python モジュールが必要です。
https://code.google.com/p/pefile/ からダウンロード、インストールしてください。

Send to プラグインについては、あなたのお好みのプログラムを呼び出せるように
launcher.py を編集してください。

ARC4 decrypt プラグインについては、PyCrypto Python モジュールが必要です。
http://www.voidspace.org.uk/python/modules.shtml#pycrypto からダウンロード、
インストールしてください。

プラグインの一覧:
* ARC4 decrypt
  選択範囲を ARC4 (Alleged RC4) で復号します。

* Binary to hex text
  選択範囲のバイナリデータを16進数のテキストに変換します。

* Byte frequency
  選択範囲の(選択していない場合は全体の)値の出現頻度を出力します。

* Bzip2 compress
  選択範囲を bzip2 アルゴリズムで圧縮します。

* Bzip2 decompress
  選択範囲を bzip2 アルゴリズムで展開します。

* Custom base64 decode
  選択範囲をカスタムbase64テーブルを使ってデコードします。

* Custom base64 encode
  選択範囲をカスタムbase64テーブルを使ってエンコードします。

* Copy to new file
  選択範囲を(選択していない場合は全体を)新しいファイルとして開きます。

* Decremental XOR
  選択範囲を XOR キーの値を減らしながら XOR します。

* Delete after
  現在のカーソル位置より後を全て削除します。

* Delete before
  現在のカーソル位置より前を全て削除します。

* Fill
  選択範囲を指定した16進数のパターンで埋めます。

* Find PE file
  選択範囲から(選択していない場合は全体から) PE ファイルを検索します。

* Guess 256 byte XOR keys
  値の出現頻度に基づいて選択範囲から(選択していない場合は全体から) 256バイトの
  長さの XOR キーを推測します。

* Gzip compress
  選択範囲を gzip 形式で圧縮します。

* Gzip2 decompress
  gzip 形式で圧縮された選択範囲を展開します。
  
* Hash values
  選択範囲の(選択していない場合は全体の) MD5, SHA1, SHA256 ハッシュ値を
  計算します。

* Hex text to binary
  選択範囲の16進数のテキストをバイナリデータに変換します。

* Incremental XOR
  選択範囲を XOR キーの値を増やしながら XOR します。

* Invert
  選択範囲のビットを反転します。

* LZNT1 compress
  選択範囲を LZNT1 アルゴリズムで圧縮します。

* LZNT1 decompress
  選択範囲を LZNT1 アルゴリズムで展開します。

* Null-preserving XOR
  選択範囲をヌルバイトと XOR キー自体をスキップしながら XOR します。

* Raw deflate
  選択範囲をヘッダとチェックサムを付けずに Deflate アルゴリズムで圧縮します。
  (PHP言語の gzdeflate() と同等)

* Raw inflate
  ヘッダとチェックサムを付けずに Deflate 圧縮された選択範囲を展開します。
  (PHP言語の gzinflate() と同等)
  
* Reverse order
  選択範囲のバイト列の順序を逆に並べ替えます。

* ROT13
  選択範囲を ROT13 アルゴリズムでデコードします。

* Send to
  選択範囲を(選択していない場合は全体を)別のプログラムで開きます。

* Swap nibbles
  選択範囲内のニブルの組を入れ替えます。

* Swap two bytes
  選択範囲内のバイトの組を入れ替えます。

* TrID
  選択範囲を(選択していない場合は全体を) TrID で開きます。

* Visual encrypt
  選択範囲をマルウェアの Zeus で使われている visual encrypt アルゴリズムで
  エンコードします。

* Visual decrypt
  選択範囲をマルウェアの Zeus で使われている visual decrypt アルゴリズムで
  デコードします。

* XOR hex search
  選択範囲から(選択していない場合は全体から) XOR またはビットローテートされて
  いるバイト列を検索します。

* XOR text search
  選択範囲から(選択していない場合は全体から) XOR またはビットローテートされて
  いる文字列を検索します。

* XOR with next byte
  選択範囲を次のバイトを XOR のキーにしながら XOR します。

作者: 萬谷 暢崇 (Email: nobutaka@nobutaka.org, Twitter: nmantani)
ライセンス: The BSD 2-Clause License (http://opensource.org/licenses/bsd-license.php)

