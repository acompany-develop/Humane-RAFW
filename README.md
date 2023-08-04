# Humane Intel SGX Remote Attestation Framework (Humane-RAFW)
## 概要
本リポジトリは、Intel SGXにおけるEPID方式のRemote Attestation（以下、RA）を「人道的な（Humane）」難易度で手軽に実現する事の出来る、RAフレームワーク（RAFW）のコードやリソースを格納しています。  

最も有名なRAのサンプルフレームワークとしては[sgx-ra-sample](https://github.com/intel/sgx-ra-sample)が挙げられますが、そちらと比較して、以下の点で様々な方に利用しやすい実装となっています（ただし、本リポジトリ自体はsgx-ra-sampleとは無関係（フォークやコピー等ではない）です）：

* 昨今SGXに求められているほとんどの利用モデルは、SGX Enclaveをサーバに配置し、クライアントがそこに秘密情報を送信して処理する「秘密計算モデル」となっています。そのような事情に合わせ、Humane-RAFWではISV（SGX側）がサーバ、SP（非SGX側）がクライアントとなる構成を取っています。（sgx-ra-sampleは真逆の構成です）

* 特定の単一の関数を1度のみ呼び出すだけでRAを最初から最後まで完遂させる事の出来る、便利なインタフェースを提供しています。

* IASとの通信においては、最新のAPIバージョン4を使用しています。

* 複雑なAutomakeやシェルスクリプトによる難解な自動生成要素を排しており、開発者は新たに加えたい要素をMakefileやコード中に簡潔に加える事が出来ます。

* SP、ISV、IAS（Intel Attestation Service）の間での通信には[cpp-httplib](https://github.com/yhirose/cpp-httplib)を採用しており、データの送受信時にはBase64コーディングをかけ、application/[json](https://github.com/nbsdx/SimpleJSON)形式で送受信を行います。これにより、sgx-ra-sampleで性能面及びユーザビリティ面で難があるmsgioに頼る必要なく、ユーザ定義の通信の実装時も近代的な方法で行う事が出来ます。

* sgx-ra-sampleが一部で取っているようなソースコード構成に比べ、可能な限り簡潔かつ整頓された構成を取っています。

* 一部の実装で行われているような簡略化されたRAではなく、Intelのドキュメントで説明されている通り、msg0〜msg4を厳密にやり取りするタイプの厳格なRAを提供しています。

* ユーザ（特にSP）によって必要な、RA特有の設定情報は、原則としてsettings.[ini](https://github.com/pulzed/mINI)内における設定で完結出来る設計になっています。詳細については後述の各種説明を参照してください。

* RA成立後のデータの安全なやり取りに利用できる、暗号化処理周りの関数を用意しています（SP側）。

* ソースコード内には適宜コメントで解説を加えており、RAの仕組みを理解したり実装する上で躓きがちな部分の解説を行っております。このコードと照らし合わせながらIntel等によるRAの仕様書を参照する事で、RAの理解の一助にもなるかと思われます。

* RAにおいて用意する必要のあるデータを簡単に生成・取得できる、補助用のツールを用意しています。

## 導入
### 動作確認環境
* OS: Ubuntu 20.04.6 LTS
* SGXSDK: バージョン2.19
* OpenSSL: バージョン1.1.1f

Windows環境には対応していません。

### SGX環境構築
[Linux-SGX](https://github.com/intel/linux-sgx)をクローンし、READMEに従ってSGXSDK及びSGXPSWを導入してください。

使用しているOSのLinuxカーネルが5.11以降である場合、SGXドライバがデフォルトで組み込まれている（in-kernelドライバ）ため、自前で導入する必要はありません。  

5.11未満のLinuxカーネルを使用している場合は、
* [linux-sgx-driver](https://github.com/intel/linux-sgx-driver)
* [linux SGX DCAP driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux)

のいずれかを導入してください。ECDSA Attestationは不要であるため、前者のドライバでも十分です。

### Humane-RAFWの展開
任意のディレクトリにて、本リポジトリをクローンしてください。


## 準備
### EPID Attestation利用登録
[こちらのページ](https://api.portal.trustedservices.intel.com/EPID-attestation)から、EPID Attestationの利用登録を行ってください。  
現時点では、**Humane-RAFWはDevelopment Access（デバッグ版Enclaveでの動作）にのみ対応**しています。  

登録後、後の手順で使用するため、管理画面で表示される以下の情報を控えておいてください。
* SPID
* Primary Key
* Secondary Key
* linkableとunlinkableのどちらを選択したか

### IASのルートCA証明書のダウンロード
RAで使用するIAS（Intel Attestation Service）のルートCA証明書を[こちら](https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem)からダウンロードし、クローンしたリポジトリのディレクトリ直下（`humane-rafw/`）に配置してください。  

直リンクからのダウンロードが不安な場合は、前述の[EPID Attestation利用登録ページ](https://api.portal.trustedservices.intel.com/EPID-attestation)の中盤あたりにある「Attestation Report Root CA Certificate:」の部分から、「PEM」の方を選択する事でも同じものを取得できます。

### https通信用のCA証明書の準備
本リポジトリではデフォルトでリポジトリのディレクトリ内に`ca-certificates.crt`の形でCA証明書を同梱しています（Ubuntu 20.04の環境からそのまま持ってきたものです）。

自前のものを用意したい場合、
* Ubuntuの場合: `/etc/ssl/certs/ca-certificates.crt`
* CentOSの場合: `/etc/pki/tls/certs/ca-bundle.crt`  

等からコピーし、ファイル名は`ca-certificates.crt`としてください。

### SPの署名用キーペアの生成・ハードコーディング
RAのセッション鍵のベースとなる共有秘密生成用のキーペア（ランタイム時に乱数的に生成される）とは別に、SPが署名に使用し、それをISVが検証する際に使用する、256bit ECDSAキーペアが必要になります。

このキーペアは、公開鍵をISVのEnclaveコード（`ISV_Enclave/isv_enclave.cpp`）にハードコーディングし、秘密鍵をSPのコード（`SP_App/sp_app.cpp`）にハードコーディングする必要があります（改竄防止のため、特に公開鍵についてはEnclaveコードへのハードコーディングがほぼ必須です）。

デフォルトでもこちらで乱数的に用意したキーペアをハードコーディングしてありますので、そのままでも問題なくRAを実行する事が出来ますが、自前のキーペアを用いたい場合は同梱の補助ツールである`sp-ecdsa-keygen`を使用できます。

このツールは、ECDSAキーペアを生成してソースコードライクに標準出力するもので、出力をコピペする事で簡単にハードコーディングを行う事が出来ます。

以下、これを用いたキーペア生成及びハードコーディングの手順を説明します：

* `sp-ecdsa-keygen`が配置されているパスに移動する。
    ```
    cd subtools/sp-ecdsa-keygen/
    ```

* `make`コマンドでビルドする。
    ```
    make
    ```

* ビルドにより生成された実行ファイルを実行する。
    ```
    ./keygen
    ```

* 以下のような内容が標準出力される。
    ```
    （前略）
    Copy the following public keys and hardcode them into ISV's Enclave code (ex: isv_enclave.cpp):

        {
                0xb5, 0x72, 0x2f, 0xb9, 0x04, 0x2d, 0xcd, 0xd9,
                0x73, 0x63, 0x42, 0x4b, 0xe2, 0xda, 0xb8, 0x7c,
                0x58, 0xf6, 0x5c, 0x5d, 0x58, 0xe8, 0x71, 0xda,
                0x69, 0x12, 0x33, 0x5b, 0x9b, 0xee, 0x73, 0x80
        },
        {
                0xef, 0x69, 0x4d, 0x3c, 0x92, 0x99, 0xae, 0x25,
                0xf4, 0x7c, 0xb8, 0x36, 0xad, 0x11, 0x47, 0x27,
                0xfa, 0x0c, 0x7d, 0xd1, 0x5d, 0x6a, 0x08, 0xd7,
                0xff, 0x01, 0x41, 0xda, 0x72, 0x19, 0xc7, 0x7f
        }



    Copy the following private key and hardcode it into SP's untrusted code (ex: sp_app.cpp):

            0x1e, 0xe0, 0x50, 0x82, 0x08, 0x57, 0x91, 0x17,
            0xa9, 0xe8, 0x51, 0x27, 0x5f, 0xf5, 0x19, 0xec,
            0xe7, 0xa9, 0x83, 0x80, 0x8d, 0xd8, 0xbc, 0x3b,
            0x5c, 0xdb, 0x2c, 0x64, 0x2a, 0x33, 0xde, 0xd6
    ```

* 上記表示の内、公開鍵の方（上側2ブロック）を、`ISV_Enclave/isv_enclave.cpp`の`static const sgx_ec256_public_t service_provider_public_key`変数の中に以下のようにコピーする。
    ``` cpp
    static const sgx_ec256_public_t service_provider_public_key = {
        {
            0xb5, 0x72, 0x2f, 0xb9, 0x04, 0x2d, 0xcd, 0xd9,
            0x73, 0x63, 0x42, 0x4b, 0xe2, 0xda, 0xb8, 0x7c,
            0x58, 0xf6, 0x5c, 0x5d, 0x58, 0xe8, 0x71, 0xda,
            0x69, 0x12, 0x33, 0x5b, 0x9b, 0xee, 0x73, 0x80
        },
        {
            0xef, 0x69, 0x4d, 0x3c, 0x92, 0x99, 0xae, 0x25,
            0xf4, 0x7c, 0xb8, 0x36, 0xad, 0x11, 0x47, 0x27,
            0xfa, 0x0c, 0x7d, 0xd1, 0x5d, 0x6a, 0x08, 0xd7,
            0xff, 0x01, 0x41, 0xda, 0x72, 0x19, 0xc7, 0x7f
        }
    };
    ```

* 同様に、秘密鍵の方（最後のブロック）を、`SP_App/sp_app.cpp`の`static const uint8_t service_provider_private_key[32]`変数の中に以下のようにコピーする。
    ``` cpp
    static const uint8_t service_provider_private_key[32] = {
        0x1e, 0xe0, 0x50, 0x82, 0x08, 0x57, 0x91, 0x17,
        0xa9, 0xe8, 0x51, 0x27, 0x5f, 0xf5, 0x19, 0xec,
        0xe7, 0xa9, 0x83, 0x80, 0x8d, 0xd8, 0xbc, 0x3b,
        0x5c, 0xdb, 0x2c, 0x64, 0x2a, 0x33, 0xde, 0xd6
    };
    ```

### Enclave署名鍵の設定
Enclaveの署名に使用する鍵は、デフォルトで`ISV_Enclave/private_key.pem`として格納しており、これを使用しています。

ただ、実運用時には自前で生成したものを使用するのが望ましいため、以下のコマンドにて新規に作成し、上記のパスに同名でその鍵を格納してください。

```
openssl genrsa -out private_key.pem -3 3072
```


### 通信の設定
デフォルトではSPとISV共に同一のマシン上に配置し、ローカルホストでポート1234を通して相互に通信する設定になっています。

この通信情報を変更したい場合、SPとISVでそれぞれ以下の箇所を編集する事で変更を行う事が出来ます。

* SPの場合：`SP_App/sp_app.cpp`の以下の箇所を編集してください。
    ``` cpp
    std::string isv_url = "http://localhost:1234";
    ```
    編集例：
    ``` cpp
    std::string isv_url = "http://example.com:1234";
    ```

* ISVの場合：`ISV_App/isv_app.cpp`の以下の箇所を編集してください。
    ``` cpp
    svr.listen("localhost", 1234);
    ```
    編集例：
    ``` cpp
    svr.listen("0.0.0.0", 1234);
    ```
    デフォルトでは明示的にローカルホストである事を明記するために`"localhost"`としていますが、基本的に`"0.0.0.0"`で問題ないはずです。より詳細は[cpp-httplibのリポジトリ](https://github.com/yhirose/cpp-httplib)を参照してください。

### RA受理条件の設定
SPにおけるRA受理判定では、本リポジトリの開発者の環境の都合上、ISVがLoad Value InjectionやÆPIC Leakに対して脆弱である事を示す`SW_HARDENING_NEEDED`とIASに判定された場合にもRAを受理するような定義にしていますが、これを不許可にする場合は、`SP_App/sp_app.cpp`の

``` cpp
else if(ra_status == "SW_HARDENING_NEEDED")
{
    /* LVIやÆPIC Leak等に脆弱である事を示しているので、理想的には許可しては
        * ならないが、便宜上今回は通すようなロジックにする */
    msg4->status = Conditionally_Trusted;
    std::string desc = std::string("Deem the Enclave as Trusted, ") +
        std::string("but ISV's platform should patch mitigations.");
    memcpy(msg4->description, desc.c_str(), desc.length());

    print_debug_message(desc, INFO);
    print_debug_message("", DEBUG_LOG);
}
```
の
``` cpp
msg4->status = Conditionally_Trusted;
```
部分を
``` cpp
msg4->status = NotTrusted;
```
に変更してください（付随して適宜その他のログメッセージ等も変更してください）。



## ビルド・設定・実行
### ビルド
準備が整ったら、makeコマンドでビルドを実行します。
```
make
```

以下のようなビルドログが出力されれば正常にビルドされています。
```
user@machine:~/Develop/sgx/sgx-related/humane-rafw$ make
GEN  =>  ISV_App/isv_enclave_u.c
CC   <=  ISV_App/isv_enclave_u.c
CXX  <=  ISV_App/isv_app.cpp
CXX  <=  ISV_App/error_print.cpp
CXX  <=  common/base64.cpp
CXX  <=  common/debug_print.cpp
CXX  <=  common/hexutil.cpp
LINK =>  isv_app
GEN  =>  ISV_Enclave/isv_enclave_t.c
CC   <=  ISV_Enclave/isv_enclave_t.c
CXX  <=  ISV_Enclave/isv_enclave.cpp
LINK =>  enclave.so
<!-- Please refer to User's Guide for the explanation of each field -->
<EnclaveConfiguration>
    <ProdID>0</ProdID>
    <ISVSVN>0</ISVSVN>
    <StackMaxSize>0x40000</StackMaxSize>
    <HeapMaxSize>0x5000000</HeapMaxSize>
    <TCSNum>10</TCSNum>
    <TCSPolicy>1</TCSPolicy>
    <DisableDebug>0</DisableDebug>
    <MiscSelect>0</MiscSelect>
    <MiscMask>0xFFFFFFFF</MiscMask>
</EnclaveConfiguration>
tcs_num 10, tcs_max_num 10, tcs_min_pool 1
INFO: Enclave configuration 'MiscSelect' and 'MiscSelectMask' will prevent enclave from using dynamic features. To use the dynamic features on SGX2 platform, suggest to set MiscMask[0]=0 and MiscSelect[0]=1.
The required memory is 88219648B.
The required memory is 0x5422000, 86152 KB.
handle_compatible_metadata: Overwrite with metadata version 0x100000004
Succeed.
SIGN =>  enclave.signed.so
CXX  <=  SP_App/sp_app.cpp
CXX  <=  common/crypto.cpp
CXX  <=  common/ias_communication.cpp
LINK =>  sp_app
user@machine:~/Develop/sgx/sgx-related/humane-rafw$ 
```

### 設定
実行する前に、RAで使用する設定情報を`settings.ini`に記載します。**デフォルトでは`settings_template.ini`というファイル名になっているので、必ずこれを`settings.ini`にリネームしてから使用してください**。

以下、`settings.ini`における各設定項目（キー）についての説明を列挙します（いずれの値もダブルクオーテーションは不要です）：
| 設定項目 | 説明 |
| -- | -- |
| SPID | EPID Attestation利用登録後に控えたSPIDを記載する。 |
| LINKABLE | Linkable/Unlinkableの内、EPID Attestation利用登録時に選択した方を指定する。0でUnlinkable、1でLinkable。 |
| IAS_PRIMARY_SUBSCRIPTION_KEY | EPID Attestation利用登録後に控えたPrimary Keyを記載する。 |
| IAS_PRIMARY_SECONDARY_KEY | Secondary Keyを記載する。 |
| IAS_REPORT_SIGNING_CA_FILE | ダウンロードしたIASルートCA証明書のファイル名（パス）を記載する。本README通りに導入した場合、この値は`Intel_SGX_Attestation_RootCA.pem`となる。 |
| MINIMUM_ISVSVN | SPがISVに要求する最小ISVSVN値。ISVSVNは、`ISV_Enclave/Enclave.config.xml`において`<ISVSVN>`タグでISVが設定する。 |
| REQUIRED_ISV_PROD_ID | SPがISVに要求するISV Product ID値。ISV Product IDは、`ISV_Enclave/Enclave.config.xml`において`<ProdID>`タグでISVが設定する。 |
| REQUIRED_MRENCLAVE | ISVに要求するMRENCLAVE値。SPは予めEnclaveのMRENCLAVEを控えておき（=ここで設定する内容）、RAにおいてISVから受け取ったQuote構造体に含まれるMRENCLAVEと比較検証を行う。この値の取得方法は後述。 |
| REQUIRED_MRSIGNER | ISVに要求するMRSIGNER値。SPは予めEnclaveのMRSIGNERを控えておき（=ここで設定する内容）、RAにおいてISVから受け取ったQuote構造体に含まれるMRSIGNERと比較検証を行う。この値の取得方法は後述。 |
| SKIP_MRENCLAVE_CHECK | 1に設定すると、RAにおいてMRENCLAVEの検証をスキップする。MRENCLAVEはEnclaveのコード等が変わる度に値が変わるため、開発時には煩雑であり、それを一時的に便宜上スキップするためのオプション。**実運用時は必ず0にする事**。 |

上記`REQUIRED_MRENCLAVE`及び`REQUIRED_MRSIGNER`で指定するMRENCLAVEやMRSIGNERは、補助ツールである`mr-extract`を使用する事で、署名済みEnclaveイメージから抽出し簡単に取得する事が出来ます。

以下、これを用いた各値の抽出方法を説明します：
* Humane-RAFW本体をビルドし、署名済みEnclaveイメージがビルドされ存在している事を確認する。
    ``` bash
    user@machine:~/Develop/sgx/sgx-related/humane-rafw$ ls -l enclave.signed.so 
    -rw-rw-r-- 1 user user 1816800 May 25 06:13 enclave.signed.so
    user@machine:~/Develop/sgx/sgx-related/humane-rafw$ 
    ```

* `mr-extract`が配置されているパスに移動する。
    ```
    cd subtools/mr-extract/
    ```

* SGXSDKや署名済みEnclaveイメージ名が以下の通りではない場合は、`mr-extract.cpp`を開き、適宜以下の部分を編集する。
    ``` cpp
    /* SGXSDKのフォルダパスはここで指定。自身の環境に合わせて変更する */
    std::string sdk_path = "/opt/intel/sgxsdk/";

    /* 署名済みEnclaveイメージファイル名はここで指定。
    * 自身の環境に合わせて変更する */
    std::string image_path = "../../enclave.signed.so";
    ```

* `make`コマンドでビルドする。
    ```
    make
    ```

* ビルドにより生成された実行ファイルを実行する。
    ```
    ./mr-extract
    ```

* 以下のような内容が標準出力される。
    ```
    -------- message from sgx_sign tool --------
    Succeed.
    --------------------------------------------

    Copy and paste following measurement values into settings.ini.
    MRENCLAVE value -> c499d7bf5c0f9fe6f7cee583e3fdaca722faa9507c17b6e317a386e0f6eeb194
    MRSIGNER value  -> babdf7eb81e8f91f1d14fa70200f76c4b49b85a3caf591faa3761d3b5910a9d5
    ```
    この例で言えば、`c499d7bf5c0f9fe6f7cee583e3fdaca722faa9507c17b6e317a386e0f6eeb194`を`REQUIRED_MRENCLAVE`に、`babdf7eb81e8f91f1d14fa70200f76c4b49b85a3caf591faa3761d3b5910a9d5`を`REQUIRED_MRSIGNER`に設定する。

### 実行
ビルドと設定が完了したら、まずISVは以下のコマンドでISVサーバを起動します：
```
./isv_app
```

ISVサーバが起動したら、SPは以下のコマンドでSPクライアントを実行します：
```
./sp_app
```

その後はRAが実行され、RAを受理した場合にはSPは秘密情報をRAのセッション鍵で暗号化してISVに送信し、ISVがEnclave内で秘密情報を足し合わせ、その結果を暗号化してSPに返却する、ごく簡単な秘密計算の例が実行されます。


## 本フレームワークの応用
### 暗号処理関数
秘密計算サンプル関数（`sample_remote_computation()`）でも使用されている`aes_128_gcm_encrypt()`関数、`aes_128_gcm_decrypt()`関数、そして`generate_nonce()`関数は、それぞれRAのセッション鍵を用いた暗号化・復号、そして初期化ベクトル等の乱数的な生成に使用する事が出来ます。

### 通信におけるデータ形式
SPとISVの間におけるデータの通信においては、各値をBase64にエンコードし、JSON形式でそれらを格納してやり取りしています。

### RAフレームワークコードの完全な切り離し
デフォルトでは、SPは`SP_App/sp_app.cpp`、ISVは`ISV_App/isv_app.cpp`にmain関数（RA実行関数を呼び出す関数）を定義しています。  
RA部分を自前のコードファイルから完全に切り離したい場合は、main関数等を自前のコードファイルで定義し、Makefileを適宜書き換えてください。  

例えば、`SP_App/my_program.cpp`を新たに追加し、この中でmain関数を宣言してRAを呼び出す場合、以下の部分：
``` makefile
## コンパイル時に使用するC/C++のソースを列挙
SP_Cpp_Files := SP_App/sp_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp common/ias_communication.cpp

```
に、以下のようにソースコードを追加します：
``` makefile
## コンパイル時に使用するC/C++のソースを列挙
SP_Cpp_Files := SP_App/sp_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp common/ias_communication.cpp SP_App/my_program.cpp

```

### 複数SPへの対応
デフォルトでは単一のISVに対して単一のSPを対応させている形ですが、複数のSPを対応させるように改修する事も可能です。  

既に、ISVはsgx_ra_context_tを用いてRAコンテキストを識別し、SPもsgx_ra_context_tを保持して適宜ISVに渡す実装になっています。  

よって、Untrusted領域レベルのロジックでのSPの識別や、SPの署名検証用公開鍵のEnclaveコードへのハードコーディング周りを整備すれば、複数SP対応についても実現する事が出来ます。


## 使用している外部ライブラリ
いずれもヘッダオンリーライブラリであり、リポジトリに組み込み済み（`include/`フォルダ内）。
* [cpp-httplib](https://github.com/yhirose/cpp-httplib): MITライセンス
* [SimpleJSON](https://github.com/nbsdx/SimpleJSON): WTFPLライセンス
* [mINI](https://github.com/pulzed/mINI): MITライセンス


## 各ディレクトリ・ファイルの説明
説明は主要なものについてのみ行っています：
* ISV_App: ISV用のEnclave外コードを格納
    * error_print.cpp: sgx_status_tを解析しエラー内容を標準出力するためのコード
    * error_print.hpp
    * isv_app.cpp: ISVのEnclave外コード。ISV側のRA処理の大部分がここに含まれる
  
* ISV_Enclave: ISVのEnclaveコード関連ファイルを格納
    * Enclave.config.xml: Enclave設定XML
    * isv_enclave.cpp: Enclaveコード
    * isv_enclave.edl: EnclaveのEDLファイル
    * private_key.pem: Enclave署名鍵
  
* SP_App: SPのメインコードを格納している
    * sp_app.cpp: SP側のメインコード。SP側のRA処理のメインもこれに含まれる

* common: 比較的汎用性の高い（例：SPとISVで共用する）か、処理としての専門性が高いコードを格納
    * attestation_status.hpp: msg4に関連する定義を宣言するヘッダ
    * base64.cpp: Base64エンコード/デコードを行うコード
    * base64.hpp
    * crypto.cpp: 主にRAに伴う暗号処理を実装するコード
    * crypto.hpp
    * debug_print.cpp: ログ標準出力用コード
    * debug_print.hpp
    * hexutil.cpp: バイナリ等を16進数表記と相互変換するコード
    * hexutil.hpp
    * ias_communication.cpp: IASとの通信を実行するコード
    * ias_communication.hpp

* include: 外部ライブラリを格納
    * httplib.h: [cpp-httplib](https://github.com/yhirose/cpp-httplib)
    * ini.h: [mINI](https://github.com/pulzed/mINI)
    * json.hpp: [SimpleJSON](https://github.com/nbsdx/SimpleJSON)

* subtools: 補助ツールを格納
    * mr-extract: MRENCLAVE及びMRSIGNERを署名済Enclaveイメージから抽出する
        * mr-extract.cpp
        * Makefile
    * sp-ecdsa-keygen: SPの署名用キーペアを生成しハードコーディング用に標準出力する
        * sp-ecdsa-keygen.cpp
        * Makefile

* .gitignore
* Makefile
* README.md
* ca-certificates.crt: OSのCA証明書をコピーして持ってきたもの
* settings_template.ini: 主にSP用の設定を列挙するためのINIファイル。**使用時には必ず`settings.ini`にリネームする事**。

## シーケンス図
![humane-rafw](https://github.com/acompany-develop/sgx-related/assets/31073471/77255c4c-bc1b-483e-9761-322339bc339e)
