######## SGX SDKに関する設定 ########

# SGXSDKの場所
SGX_SDK ?= /opt/intel/sgxsdk
# 動作モード。ここではHWかSIM。make SGX_MODE=SIMのようにしてオプションで指定可能
SGX_MODE ?= HW
# マシンのアーキテクチャ。32bitか64bit
SGX_ARCH ?= x64
# Enclaveのデバッグモード。1ならDebug版、0なら製品版
SGX_DEBUG ?= 1


## マシンが32bitであればアーキテクチャの変数を更新する
ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif


## アーキテクチャに応じて使用するSGXSDKのツールを設定する
#  32bit版の場合
ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32                         # コンパイル時の共通オプション
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib                # SGX関係のライブラリの場所
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign # SGX署名ツールの場所
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r     # Edger8r Toolの場所
#  64bit版の場合。それぞれの変数の内訳は同上
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif


## DEBUGモードとPRERELEASEモードは同時に有効にできないので弾く
ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif


## DEBUGモード有無に応じてコンパイル共通フラグに追記
ifeq ($(SGX_DEBUG), 1)
		SGX_COMMON_CFLAGS += -O0 -g # 最適化なし、コンパイル時デバック情報表示
else
		SGX_COMMON_CFLAGS += -O2    # 最適化あり
endif



######## SP側Enclave外アプリケーション（SP_App）に関する設定 ########

## コンパイル時に使用するC/C++のソースを列挙
SP_Cpp_Files := SP_App/sp_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp common/ias_communication.cpp

## 使用するincludeファイル（ヘッダ）がある場所を列挙
SP_Include_Paths := -ISP_App -I$(SGX_SDK)/include -Icommon -Iinclude

## SP_Appのコンパイル時に使用するオプションを指定。
SP_C_Flags := $(SGX_COMMON_CFLAGS) $(SP_Include_Paths)

## 実際にはC++コンパイルするので、それ用の最終的なオプションを生成
SP_Cpp_Flags := $(SP_C_Flags) -std=c++11 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

## リンクオプション
SP_Link_Flags := $(SGX_COMMON_CFLAGS) -lpthread -lcrypto -lssl

## オブジェクトファイルを指定
SP_Cpp_Objects := $(SP_Cpp_Files:.cpp=.o)

## UntrustedのAppの実行バイナリ名を指定
SP_App_Name := sp_app


######## ISV側Enclave外アプリケーション（ISV_App）に関する設定 ########

## シミュレーションモードの場合は専用のUntrusted用ライブラリを用いる
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

## コンパイル時に使用するC/C++のソースを列挙
App_Cpp_Files := ISV_App/isv_app.cpp ISV_App/error_print.cpp common/base64.cpp \
				common/debug_print.cpp common/hexutil.cpp

## 使用するincludeファイル（ヘッダ）がある場所を列挙
App_Include_Paths := -IISV_App -I$(SGX_SDK)/include -Icommon -Iinclude

## Appのコンパイル時に使用するオプションを指定。
#  共通オプション、位置独立コード、不明なスコープ属性への警告を無視、Includeパス
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)


## EnclaveのDEBUGモードに応じてデバッグ可否のフラグをCコンパイルオプションに追加する。
#   Debug - DEBUGフラグを付与（デバッグ可）
#   Prerelease - NDEBUG（NO DEBUGの意）フラグとDEBUGフラグ双方を付与（デバッグ可らしい）
#   Release - NDEBUGフラグを付与（デバッグ不可）
#
#   これ必要？
#ifeq ($(SGX_DEBUG), 1)
#		App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
#else ifeq ($(SGX_PRERELEASE), 1)
#		App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
#else
#		App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
#endif


## 実際にはC++コンパイルするので、それ用の最終的なオプションを生成
App_Cpp_Flags := $(App_C_Flags) -std=c++11 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

## リンクオプション
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) \
            		-Wl,--whole-archive  -lsgx_uswitchless -Wl,--no-whole-archive \
					-lsgx_ukey_exchange \
					-l$(Urts_Library_Name) -lpthread -lcrypto -lssl

## シミュレーションモードの場合は専用のライブラリを紐付ける
ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

## オブジェクトファイルを指定
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

## UntrustedのAppの実行バイナリ名を指定
App_Name := isv_app



######## ISVのEnclaveアプリケーションに関する設定 ########
## シミュレーションモードの場合は専用のTrusted用ライブラリを用いる
ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif


## SGX用暗号ライブラリを指定（他にはIntel IPPなどが使えるはず）
Crypto_Library_Name := sgx_tcrypto

## コンパイル時に使用するC/C++のソースを列挙
Enclave_Cpp_Files := ISV_Enclave/isv_enclave.cpp

## 使用するincludeファイル（ヘッダ）がある場所を列挙
Enclave_Include_Paths := -IISV_Enclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport \
						-I$(SGX_SDK)/include/libcxx -Icommon


## Enclaveのコンパイル時に使用するオプションを指定。
#  共通オプション、通常のincludeファイルを検索しない（SGX専用のを使う）、
#  シンボルの外部隠蔽、位置独立実行形式、スタック保護有効化、使用するIncludeファイルのパス
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)

## 実際にはC++コンパイルするので、それ用の最終的なオプションを生成
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

## 多すぎるので詳細はDeveloper Reference参照。Switchless CallのIncludeを忘れない事。
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -lsgx_tswitchless -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0
	# -Wl,--version-script=Enclave/Enclave.lds


## オブジェクトファイルを設定
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)


## Enclaveイメージ名とEnclave設定ファイル名の設定
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := ISV_Enclave/Enclave.config.xml


## HWモードかつRELEASEモードの際は専用のフラグを設定
ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


## makeコマンド向け設定
#  make時にallコマンドとrunコマンドに対応（例：make all）
.PHONY: all run

## ややこしいが、Makefileはその場で依存関係が解決できない場合は後続の行を見に行くため、
## allやrunの内容はMakefileのこの行までの記述で実現はできない（Makeが後ろの方を勝手に見てくれる）

## RELEASEモードの場合のみ署名に関するメッセージを表示
ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
## RELEASEでない場合はビルドのみ実行（その際後続の処理を参照する）
all: $(App_Name) $(Signed_Enclave_Name) $(SP_App_Name)
endif

run: all # runはallの結果に依存
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif



######## SP側Appオブジェクト関する設定（つまりビルド設定） ########

## Appのオブジェクトファイルを生成。$(CC)は暗黙のルールにより、デフォルトでg++コマンド。
SP_App/%.o: SP_App/%.cpp
	@$(CXX) $(SP_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

## commonフォルダ内のコードについても同様にオブジェクトファイルを生成
common/%.o: common/%.cpp
	@$(CXX) $(SP_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

## リンクによりSP_Appの実行ファイルを生成
$(SP_App_Name): $(SP_Cpp_Objects)
	@$(CXX) $^ -o $@ $(SP_Link_Flags)
	@echo "LINK =>  $@"



######## ISV側Appオブジェクト関する設定（ビルド設定） ########

## Edger8rによりUntrusted向けエッジ関数のソースを生成
ISV_App/isv_enclave_u.c: $(SGX_EDGER8R) ISV_Enclave/isv_enclave.edl
	@cd ISV_App && $(SGX_EDGER8R) --untrusted ../ISV_Enclave/isv_enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

## ソースによりエッジ関数のオブジェクトファイルを生成。$(CC)は暗黙のルールにより、デフォルトでccコマンド。
ISV_App/isv_enclave_u.o: ISV_App/isv_enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## Appのオブジェクトファイルを生成。$(CC)は暗黙のルールにより、デフォルトでg++コマンド。
ISV_App/%.o: ISV_App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

## リンクによりAppの実行ファイルを生成
$(App_Name): ISV_App/isv_enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclaveオブジェクト関する設定（ビルド設定） ########

## Edger8rによりTrusted向けエッジ関数のソースを生成
ISV_Enclave/isv_enclave_t.c: $(SGX_EDGER8R) ISV_Enclave/isv_enclave.edl
	@cd ISV_Enclave && $(SGX_EDGER8R) --trusted ../ISV_Enclave/isv_enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

## ソースによりエッジ関数のオブジェクトファイルを生成
ISV_Enclave/isv_enclave_t.o: ISV_Enclave/isv_enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## Enclaveのオブジェクトファイルを生成
ISV_Enclave/%.o: ISV_Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

## Enclaveの未署名イメージ（共有ライブラリ）の生成
$(Enclave_Name): ISV_Enclave/isv_enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

## Enclave未署名イメージに対しsgx_signで署名を実施
$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key ISV_Enclave/private_key.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"



## クリーンアップ用サブコマンドの定義
.PHONY: clean

clean:
	@rm -f $(App_Name) $(SP_App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) $(SP_Cpp_Objects) ISV_App/isv_enclave_u.* $(Enclave_Cpp_Objects) ISV_Enclave/isv_enclave_t.*