# 第一章 リバースエンジニアリングのためだけのアセンブラ
## レジスタ
CPUが使用する単なる変数と考えてよい。
### EAX
`A`は`Accumulator`を示す。算術計算と戻り値の保存の役割をする。関数の戻り値や `return 100`, `return FALSE`などのコードを使用するとき、これらの`100`や`FALSE`に相当する値がすぐにEAXに入る事が多い。
### EDX
`D`は`Data`を示す。EAXと役割は同じだが戻り値の保存には使用されない。算術演算に使用される。
### ECX
`C`は`Count`を示す。ループを実行するときにカウントする役割をする。`for`文の`i`のようなもの。`for`文では`i`をインクリメントすることが多いが、ECXは逆に前もってループの回数分の値を入れておき、0になるまでデクリメントする。
### EBX
特に指定された用途はない。前の3つのレジスタで足りない場合に使用される。
### ESI, EDI
`S`は`Source`、`D`は`Destination`を示す。前の4つのレジスタが主に演算に利用されるの対し、ESIは文字列やデータの処理における繰り返し処理やメモリの内容の移動に使われる。ESIとEDIはそれぞれメモリのスタートアドレスと目的地アドレスを示すと考えて良い。
## スタック
関数内でスタックを使用すると通常次のようなコードが関数のエントリポイントに生成される。
```assembly
push ebp
mov ebp, esp
sub esp, 50h
```
このコードの流れは以下。
1. ESPレジスタの内容をスタックに入れる
2. ESPの値をEBPに入れる
3. ESPから`50h`を引く
この部分においてローカル変数とは関数内の変数を意味する。
2までの部分でEBPとESPが同じ値になり、この関数内のローカル変数はすべてEBPから計算できるようになる(ESPはスタックポインタ)。EBPを基準としてオフセットを足し引きするだけでスタックの処理ができるようになる。
3ではスタックのLIFOの性質に基づき、引いた値の分(`50h`の容量)だけスタックを使用するということになる。
EBPの内容あh現在の関数でスタックの一番上にあり、最初のアドレスとなった。サイズを引きながらスペースを確保するのでローカル変数はマイナスを使って計算できる。変数が4バイトずつ確保すると仮定した場合、`ebp-4`は最初のローカル変数、`ebp-8`は二番目のローカル変数になる。
## 関数呼び出し
以下のDWORD型の3つの引数を受け取る関数について考える。
```c
DWORD HelloFunction(DWORD dwParam1, DWORD dwParam2, DWORD dwparam3)
```
この関数を呼び出す。
```c
main() {
  DWORD dwRet = HelloFunction(0x37, 0x38, 0x39);
  if(dwRet)
  // ....
}
```
上のコードをリバースすると以下のようになる。
```assembly
push 39h
push 38h
push 37h
call 401300h
```
関数の引数はLIFOの順序でスタックに入れるため、実際のソースコードで呼び出される順序と逆になる。
4行目について、以前のコードでは`mov esp, ebp`を利用したのでローカル変数は`ebp-x`のようにスタックに保存された変数をマイナス方向で使用したが、今度はパラメータをpushで入れたので、これらの値にアクセスするためにはパラメータは`ebp+x`の形式でオフセットに足すことで計算できる。`ebp+8`が最初の引数である`37h`、`ebp+0xc`が2番目の引数である`38h`、`ebp+0x10`が3番目の引数である`39h`になる。
ただし`ebp+4`には関数の処理が終わって復帰するときに使用するリターンアドレスが入る。
# 第二章 C言語の文法と逆アセンブル
## 関数の基本的な構造
以下のプログラムとアセンブリを考える。
```c
int sum(int a, int b) {
  int c = a + b;
  return c;
}
```

```assembly
push ebp
mov ebp, esp
push ecx
mov eax, [ebp+arg_0]
add eax, [ebp+arg_4]
mov [ebp+var_4], eax
mov eax, [ebp+var_4]
mov esp, ebp
pop ebp
retn
```
関数の始まりには`push ebp`、関数の終わりには`pop ebp`が対応することが多い。
まず関数の始まり部分に対応する以下の部分について考える。
```assembly
push ebp
mov ebp, esp
```
EBPはスタックのベースポインタであり、`push ebp`でこれまでのベースアドレスをスタックに保存する。その後`mov ebp, esp`で現在のスタックポインタESPをEBPに入れる。つまりこれまで基準となっていたスタックのベースポインタのバックアップを作成し、新しいスタックポインタを使用するという流れになる。
次に関数の終了に対応する以下の部分について考える。
```assembly
mov esp, ebp
pop ebp
```
関数が終了すると、バックアップしておいたベースアドレスをESPに代入して戻してからEBPをスタックから取り除く。これによって今まで関数で使用していたスタックの位置がもとに戻る。
## 関数の呼び出し規約
リバースエンジニアリングにおいては各関数の役割を理解することが必要になる。それに先行する作業として関数の形式や引数についての情報を抽出することが必要になる。
関数の呼び出し規約には主に以下の4通りがある。
- `__cdecl`
- `__stdcall`
- `__fastcall`
- `__thiscall`
逆アセンブルされたコードを読んだときに用いられている呼び出し規約を把握できるようになることで、call文を見て関数の引数の個数や用途を分析できる。
### __cdecl
C
```c
int __cdecl sum(int a, int b) {
  int c = a + b;
  return c;
}

int main(int args, char* argv[]) {
  sum(1, 2);
  return 0;
}
```

アセンブリ
```assembly
sum:
push ebp
mov ebp, esp
push ecx
mov eax, [ebp+arg_0]
add eax, [ebp+arg_4]
mov [ebp+var_4], eax
mov eax, [ebp+var_4]
mov esp, ebp
pop ebp
retn

main:
push 2
push 1
call calling.00401000
add esp, 8
```
`call calling.00401000`で関数を呼び出している。次に`call`の次の行では`add esp, 8`でスタックを調整しているので`__cdecl`方式の関数だと推測できる。さらに引数は4バイトずつ計算されるのでスタックを8バイトまで引き上げている点から引数を2つ持つ関数であることが把握できる。また関数の最後の部分でEAXに入る値が数値なので戻り値はアドレスなどの値ではなく数値であることもわかる。
### __stdcall
C
```c
int __stdcall sum(int a, int b) {
  int c = a + b;
  return c;
}

int main(int args, char* argv[]) {
  sum(1, 2);
  return 0;
}
```

アセンブリ
```assembly
sum:
push ebp
mov ebp, esp
push ecx
mov eax, [ebp+arg_0]
add eax, [ebp+arg_4]
mov [ebp+var_4], eax
mov eax, [ebp+var_4]
mov esp, ebp
pop ebp
retn 8

main:
push 2
push 1
call calling.00401000
```
先の`__cdecl`との違いは`add esp, 8`がない代わりにsumのreturn文として`retn`ではなく`retn 8`を実行している点である。このように`__stdcall`方式では関数内でスタックを処理するので、8バイトのスタック調整から引数が2つであるという判断は関数の内部で行う必要がある。Win32 APIでは主に`__stdcall`方式が採用されている。
`retn`があって`retn 10`のように数値オペランドを指定せずにcallした後に`add esp, x`も見当たらなかったらその関数は`__stdcall`方式で引数がないタイプであるといえる。
### __fastcall
C
```c
int __fastcall sum(int a, int b) {
  int c = a + b;
  return c;
}

int main(int args, char* argv[]) {
  sum(1, 2);
  return 0;
}
```

アセンブリ
```assembly
sum:
push ebp
mov ebp, esp
sub esp, 0Ch
mov [ebp+var_C], edx
mov [ebp+var_8], ecx
mov eax, [ebp+var_8]
add eax, [ebp+var_C]
mov [ebp+var_4], eax
mov eax, [ebp+var_4]
mov esp, ebp
pop ebp
retn

main:
push ebp
mov ebp, esp
mov edx, 2
mov exc, 1
call sub_401000
xor eax, eax
pop ebp
retn
```
`sub esp, 0Ch`でスタック領域を確保してEDXレジスタを使用している。`fastcall`は関数の引数が2つ以下の場合、引数を渡すときにpushを使用せず、ECXレジスタとEDXレジスタを使用する。メモリを使用するよりもレジスタを使用したほうがはるかに高速になるので`fastcall`は引数が2個以下で頻繁に使用される関数に使われるのが一般的。
関数の呼び出しの前にEDXレジスタとECXレジスタに値を入れる箇所があったら`fastcall`規約の関数だと判断できる。
### __thiscall
C++
```C++
Class CTemp {
  public:
    int MemberFunc(int a, int b);
};
```

アセンブリ
```assembly
mov eax, dword ptr [ebp-14h]
push eax
mov edx, dword prt [ebp-10h]
push edx
lea ecx, [ebp-4]
call 402000
```
C++のクラスで使用される。現在のオブジェクトのポインターをECXに入れて渡す。この渡される値がthisポインターであり、クラスで使用しているメンバ変数や各種の値は次のようにECXポインターにオフセットのアドレス値を足す形で使用できる。
```assembly
ecx+x
ecx+y
ecx+z
```
引数を渡す方法やスタックの処理方法は`__stdcall`と同じ。