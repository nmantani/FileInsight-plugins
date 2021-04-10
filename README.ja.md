# FileInsight-plugins: McAfee FileInsight バイナリエディタのマルウェア解析用デコードツールボックス

FileInsight-plugins は McAfee FileInsight バイナリエディタ用のプラグイン集です。
暗号の復号、圧縮の展開、XOR された文字列の検索、YARA ルールでのスキャン、コードのエミュレーション、逆アセンブル等、多数の機能を追加できます。
マルウェア解析に関する様々なデコード作業に便利です。（例：文書ファイル型のマルウェアからマルウェアの実行ファイルやダミーの文書ファイルを抽出する）

## スクリーンショット
#### AES decrypt プラグインのダイアログ
![screenshot1.png](docs/screenshot1.png)

#### YARA scan プラグインの実行結果
![screenshot2.png](docs/screenshot2.png)

#### Parse file structure プラグインで ELF ファイルの構造をパースした結果
![screenshot3.png](docs/screenshot3.png)

#### Emulate code プラグインで ARM64 の Linux 用のシェルコードをエミュレートした結果
![screenshot4.png](docs/screenshot4.png)

#### Disassemble プラグインで x86 の Linux 用のシェルコードを逆アセンブルした結果
![screenshot5.png](docs/screenshot5.png)

#### Bitmap view プラグインで Windows の実行ファイルを可視化した結果
![screenshot6.png](docs/screenshot6.png)

#### Byte histogram プラグインで表示した Excel ファイル中の値の出現頻度のグラフ
![screenshot7.png](docs/screenshot7.png)

#### Entropy graph プラグインで表示した Windows の実行ファイルのエントロピーのグラフ
![screenshot8.png](docs/screenshot8.png)

## インストール方法
### 自動でのインストール
以下のコマンドを実行してください。最新のリリース版の FileInsight-plugins と FileInsight、Python 3 (x64) を含む全ての必要なものがインストールされます。

```
powershell -exec bypass -command "IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))"
```

HTTP プロキシをお使いの場合は [install.ps1](https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1) をダウンロードして、ファイル中の $PROXY_HOST と
$PROXY_PORT の変数を編集してから以下のコマンドを実行してください。

```
powershell -exec bypass .\install.ps1
```

## 手動でのインストール
詳しくは [INSTALL.ja.md](INSTALL.ja.md) をお読みください。
手動でのインストールは多数の手順が必要となりますので、**自動でのインストールを強くおすすめします。**

## 使い方
Plugins タブにある "Operations" をクリックして、プラグインを選択してください。

<img src="docs/how_to_use1.png" width="370" height="274">

右クリックのメニューからプラグインを使用することもできます。

![how_to_use2.png](docs/how_to_use2.png)

いくつかのプラグインは使用時に設定のダイアログを表示します。

![how_to_use3.png](docs/how_to_use3.png)

## アップデート方法
### 半自動でのアップデート
FileInsight-plugins を最新のリリース版にアップデートしたい場合は以下のコマンドを実行してください。既存のファイルは上書きされます。

```
powershell -exec bypass -command "& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))) -update"
```

HTTP プロキシをお使いの場合は install.ps1 をダウンロードして、ファイル中の $PROXY_HOST と
$PROXY_PORT の変数を編集してから以下のコマンドを実行してください

```
powershell -exec bypass .\install.ps1 -update
```

### 手動でのアップデート
最新のリリース版をダウンロードして plugins フォルダを %USERPROFILE%\Documents\McAfee FileInsight
に上書きコピーしてください。

## カスタマイズ
Send to プラグインはファイルをあなたのお好みのプログラムで開くことができます。
Send to プラグインのメニューで Customize menu をクリックしてください。

<img src="docs/customization1.png" width="364" height="176">

"plugins\Operations\Misc\send_to.json" がデフォルトのテキストエディタで開かれます。編集して保存してください。

![customization2.png](docs/customization2.png)

カスタマイズした内容がメニューに反映されます。

<img src="docs/customization3.png" width="392" height="276">

## プラグインの一覧 (110個)
### Basic operations
* Copy to new file  
  選択範囲を(選択していない場合は全体を)新しいファイルとして開きます。
* Bookmark  
  選択範囲を指定したコメントと色でブックマークします。
* Cut binary to clipboard  
  選択範囲のバイナリデータをクリップボードに切り取ります(16進テキストとして)。
* Copy binary to clipboard  
  選択範囲のバイナリデータをクリップボードにコピーします(16進テキストとして)。
* Paste binary from clipboard  
  クリップボードからバイナリデータをペーストします(16進テキストから変換)。
  Paste binary data (converted from hex-encoded text) from clipboard
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

### Compression operations
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
* LZ4 compress  
  選択範囲を LZ4 アルゴリズムで圧縮します。
* LZ4 decompress  
  選択範囲を LZ4 アルゴリズムで展開します。
* LZMA compress  
  選択範囲を LZMA アルゴリズムで圧縮します。
* LZMA decompress  
  選択範囲を LZMA アルゴリズムで展開します。
* LZNT1 compress  
  選択範囲を LZNT1 アルゴリズムで圧縮します。
* LZNT1 decompress  
  選択範囲を LZNT1 アルゴリズムで展開します。
* LZO compress  
  選択範囲を LZO アルゴリズムで圧縮します。
* LZO decompress  
  選択範囲を LZO アルゴリズムで展開します。
* PPMd compress  
  選択範囲を PPMd アルゴリズムで圧縮します。
* PPMd decompress  
  選択範囲を PPMd アルゴリズムで展開します。
* QuickLZ compress  
  選択範囲を QuickLZ 圧縮ライブラリで圧縮します。
* QuickLZ decompress  
  選択範囲を QuickLZ 圧縮ライブラリで展開します。
* Raw deflate  
  選択範囲をヘッダとチェックサムを付けずに Deflate アルゴリズムで圧縮します。(PHP言語の gzdeflate() と同等)
* Raw inflate  
  ヘッダとチェックサムを付けずに Deflate 圧縮された選択範囲を展開します。(PHP言語の gzinflate() と同等)
* XZ compress  
  選択範囲を XZ 形式で圧縮します。
* XZ decompress  
  選択範囲を XZ 形式として展開します。
* zlib compress (deflate)  
  選択範囲を zlib (Deflate アルゴリズム) で圧縮します。
* zlib decompress (inflate)  
  選択範囲を zlib (Deflate アルゴリズム) で展開します。
* Zstandard compress  
  選択範囲を Zstandard アルゴリズムで圧縮します。
* Zstandard decompress  
  選択範囲を Zstandard アルゴリズムで展開します。

### Crypto operations
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
* TEA decrypt  
  選択範囲を TEA (Tiny Encryption Algorithm) で復号します。
* TEA encrypt  
  選択範囲を TEA (Tiny Encryption Algorithm) で暗号化します。
* Triple DES decrypt  
  選択範囲を Triple DES で復号します。
* Triple DES encrypt  
  選択範囲を Triple DES で暗号化します。
* XTEA decrypt  
  選択範囲を XTEA (eXtended Tiny Encryption Algorithm) で復号します。
* XTEA encrypt  
  選択範囲を XTEA (eXtended Tiny Encryption Algorithm) で暗号化します。

### Encoding operations
* Binary data to hex text  
  選択範囲のバイナリデータを16進数のテキストに変換します。
* Hex text to binary data  
  選択範囲の16進数のテキストをバイナリデータに変換します。
* Binary data to decimal text  
  選択範囲のバイナリデータを10進数のテキストに変換します。
* Decimal text to binary data  
  選択範囲の10進数のテキストをバイナリデータに変換します。
* Binary data to octal text  
  選択範囲のバイナリデータを8進数のテキストに変換します。
* Octal text to binary data  
  選択範囲の8進数のテキストをバイナリデータに変換します。
* Binary data to binary text  
  選択範囲のバイナリデータを2進数のテキストに変換します。
* Binary text to binary data  
  選択範囲の2進数のテキストをバイナリデータに変換します。
* Custom base16 decode  
  選択範囲をカスタムbase16テーブルを使ってデコードします。
* Custom base16 encode  
  選択範囲をカスタムbase16テーブルを使ってエンコードします。
* Custom base32 decode  
  選択範囲をカスタムbase32テーブルを使ってデコードします。
* Custom base32 encode  
  選択範囲をカスタムbase32テーブルを使ってエンコードします。
* Custom base58 decode  
  選択範囲をカスタムbase58テーブルを使ってデコードします。
* Custom base58 encode  
  選択範囲をカスタムbase58テーブルを使ってエンコードします。
* Custom base64 decode  
  選択範囲をカスタムbase64テーブルを使ってデコードします。
* Custom base64 encode  
  選択範囲をカスタムbase64テーブルを使ってエンコードします。
* Custom base85 decode  
  選択範囲をカスタムbase85テーブルを使ってデコードします。
* Custom base85 encode  
  選択範囲をカスタムbase85テーブルを使ってエンコードします。
* Protobuf decode  
  選択範囲を Protocol Buffers でシリアライズされたデータとして .proto ファイル無しでデコードします。
* ROT13  
  選択範囲のアルファベットの文字列を指定した数だけローテートします。(デフォルト: 13)
* From quoted printable  
  選択範囲を quoted printable としてデコードします。
* To quoted printable  
  選択範囲を quoted printable としてエンコードします。
* Unicode escape  
  選択範囲の Unicode 文字列をエスケープします。
* Unicode unescape  
  選択範囲の Unicode エスケープシーケンスを文字列に戻します。
* URL decode  
  選択範囲を URL に使われているパーセントでエンコードされたテキストとしてデコードします。
* URL encode  
  選択範囲を URL に使われているパーセントでエンコードされたテキストとしてエンコードします。

### Misc operations
* Emulate code  
  選択範囲を(選択していない場合は全体を) Qiling Framework でエミュレートします。
* File comparison  
  2つのファイルの内容を比較します。
* Hash values  
  選択範囲の(選択していない場合は全体の) MD5, SHA1, SHA256, ssdeep, imphash, impfuzzy ハッシュ値を計算します。
* Send to  
  選択範囲を(選択していない場合は全体を)別のプログラムで開きます。

### Parsing operations
* Binwalk scan  
  選択範囲を(選択していない場合は全体を)スキャンして埋め込まれたファイルを探します。
* Disassemble  
  選択範囲を(選択していない場合は全体を)逆アセンブルします。
* File type  
  選択範囲の(選択していない場合は全体の)ファイルの種類を判別します。
* Find PE file  
  選択範囲から(選択していない場合は全体から) PE ファイルを検索します。
* Parse file structure  
  選択範囲を(選択していない場合は全体を) のファイル構造を Kaitai Struct でパースします。
* Show metadata  
  選択範囲の(選択していない場合は全体の)ファイルのメタデータを ExifTool を使って表示します。
* Strings  
  選択範囲から(選択していない場合は全体から)文字列を抽出します。

### Search operations
* Regex search  
  選択範囲から(選択していない場合は全体から) 正規表現で検索します。
* Replace  
  選択範囲から(選択していない場合は全体から) 検索してマッチした領域を指定したデータで置換します。
* XOR hex search  
  選択範囲から(選択していない場合は全体から) XOR またはビットローテートされているバイト列を検索します。
* XOR text search  
  選択範囲から(選択していない場合は全体から) XOR またはビットローテートされている文字列を検索します。
* YARA scan  
  選択範囲を(選択していない場合は全体を) YARA でスキャンします。

### Visualization operations
* Bitmap view  
  ファイル全体をビットマップとして可視化します。
* Byte histogram  
  選択範囲の(選択していない場合は全体の)値の出現頻度のグラフを出力します。
* Entropy graph  
  選択範囲の(選択していない場合は全体の)エントロピーのグラフを出力します。

### XOR operations
* Decremental XOR  
  選択範囲を XOR キーの値を減らしながら XOR します。
* Incremental XOR  
  選択範囲を XOR キーの値を増やしながら XOR します。
* Null-preserving XOR  
  選択範囲をヌルバイトと XOR キー自体をスキップしながら XOR します。
* XOR with next byte  
  選択範囲を次のバイトを XOR のキーにしながら XOR します。
* Guess multibyte XOR keys  
  0x00 と XOR することによって現れているキーの値に基づいて選択範囲から(選択していない場合は全体から)複数バイトの XOR キーを推測します。
* Visual encrypt  
  選択範囲をマルウェアの Zeus で使われている visual encrypt アルゴリズムでエンコードします。
* Visual decrypt  
  選択範囲をマルウェアの Zeus で使われている visual decrypt アルゴリズムでデコードします。

## 作者
萬谷 暢崇 (Twitter: @nmantani)

## ライセンス
The BSD 2-Clause License (http://opensource.org/licenses/bsd-license.php)
