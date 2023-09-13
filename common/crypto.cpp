#include <openssl/cmac.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <algorithm>
#include <sgx_key_exchange.h>
#include "crypto.hpp"

#define PKEY_ECDSA_256_PUBKEY_LENGTH 65


/* このソースコードの関数向けの初期化（事前処理） */
void crypto_init()
{
	/* libcryptoのエラー文字列を全ロード */
	ERR_load_crypto_strings();

	/* OpenSSL関連の全アルゴリズムをロード */
	OpenSSL_add_all_algorithms();
}


/* OpenSSLのEVP形式のECDSA-256bitキーペアを生成 */
EVP_PKEY* evp_pkey_generate()
{
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *param_ctx = NULL;
	EVP_PKEY_CTX *key_ctx = NULL;
	EVP_PKEY *params = NULL;

	do
	{
		/* EVPのパラメータコンテキストを生成 */
		param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
		if(param_ctx == NULL) return NULL;

		/* NIST P-256曲線ベースのパラメータを生成 */
		if(!EVP_PKEY_paramgen_init(param_ctx)) break;

		if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, NID_X9_62_prime256v1)) break;

		if(!EVP_PKEY_paramgen(param_ctx, &params)) break;

		/* 鍵生成処理を実行 */
		key_ctx = EVP_PKEY_CTX_new(params, NULL);
		if(key_ctx == NULL) break;

		if(!EVP_PKEY_keygen_init(key_ctx)) break;

		if(!EVP_PKEY_keygen(key_ctx, &key)) break;

	} while(false);

	if(key_ctx != NULL) EVP_PKEY_CTX_free(key_ctx);
	if(params != NULL) EVP_PKEY_free(params);
	if(param_ctx != NULL) EVP_PKEY_CTX_free(param_ctx);

	return key;
}


/* 共有秘密Gab_xを導出 */
uint8_t* derive_shared_secret(EVP_PKEY *Ga, EVP_PKEY *Gb, size_t &secret_len)
{
	EVP_PKEY_CTX *secret_ctx = NULL;
	uint8_t *shared_secret = NULL; //Gab_xを格納

	secret_len = 0;

	do
	{
		secret_ctx = EVP_PKEY_CTX_new(Gb, NULL);
		if(secret_ctx == NULL) break;

		if(!EVP_PKEY_derive_init(secret_ctx)) break;

		if(!EVP_PKEY_derive_set_peer(secret_ctx, Ga)) break;

		/* 格納先バッファをNULLにする事で、共有秘密の長さだけを取得 */
		if(!EVP_PKEY_derive(secret_ctx, NULL, &secret_len)) break;

		/* 共有秘密のサイズ分メモリを確保 */
		shared_secret = (uint8_t*)OPENSSL_malloc(secret_len);
		if(shared_secret == NULL) break;

		/* 共有秘密の生成。厳密には生成された共有秘密の内x成分から
		 * 導出される256bitの値 */
		if(!EVP_PKEY_derive(secret_ctx, shared_secret, &secret_len))
		{
			OPENSSL_free(shared_secret);
			shared_secret = NULL;
		}

	} while(false);

	if(secret_ctx != NULL) EVP_PKEY_CTX_free(secret_ctx);

	return shared_secret;
}


/* EVP形式のECDSA-256bit公開鍵をsgx_ec256_public_tに変換 */
int evp_pubkey_to_sgx_ec256(sgx_ec256_public_t *sgx_pubkey, EVP_PKEY *pkey)
{
	/* uint8_t配列に変換 */
	int pkey_len;
	uint8_t *u_pkey, *u_tmp;
	pkey_len = i2d_PublicKey(pkey, NULL);
	u_pkey = (uint8_t*)malloc(pkey_len + 1);
	
	// EVP形式の256bit ECDSA公開鍵は必ず65バイトになるはずである
	if(pkey_len != PKEY_ECDSA_256_PUBKEY_LENGTH)
	{
		std::cerr << "corrupted pubkey." << std::endl;
		return -1;
	}

	u_tmp = u_pkey;
	i2d_PublicKey(pkey, &u_tmp);

	uint8_t pkey_gx[SGX_ECP256_KEY_SIZE]; //SP公開鍵のx成分
	uint8_t pkey_gy[SGX_ECP256_KEY_SIZE]; //SP公開鍵のy成分
	// SGX_ECP256_KEY_SIZEはsgx_key_exchange.hがincludeしている
	// sgx_tcrypto.hにて定義されている。デフォルトで32。

	/* 先頭1バイト(メタデータ)を除去しx, y成分を抽出 */
	for(int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
	{
		pkey_gx[i] = u_pkey[i + 1];
		pkey_gy[i] = u_pkey[i + 1 + SGX_ECP256_KEY_SIZE];
	}

	/* sgx_ec256_public_tに合わせるためリトルエンディアン化 */
	std::reverse(pkey_gx, pkey_gx + 32);
	std::reverse(pkey_gy, pkey_gy + 32);

	for (int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
	{
		sgx_pubkey->gx[i] = pkey_gx[i];
		sgx_pubkey->gy[i] = pkey_gy[i];
	}

	return 0;
}


/* sgx_ec256_public_tからEVP_PKEY公開鍵に変換 */
EVP_PKEY* evp_pubkey_from_sgx_ec256(sgx_ec256_public_t *sgx_pubkey)
{
	EVP_PKEY_CTX *pkey_ctx;
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM_BLD *param_bld;
	OSSL_PARAM *params = NULL;
	uint8_t *pubkey = NULL;
	BIGNUM *bn_gx = NULL;
	BIGNUM *bn_gy = NULL;
	int error_flag = 0;

	try
	{
		param_bld = OSSL_PARAM_BLD_new();
		if(param_bld == NULL) throw std::exception();

		if(!OSSL_PARAM_BLD_push_utf8_string(param_bld, 
			OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0))
				throw std::exception();

		pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if(pkey_ctx == NULL) throw std::exception();

		if(EVP_PKEY_fromdata_init(pkey_ctx) <= 0)
			throw std::exception();

		size_t pubkey_size = sizeof(sgx_pubkey->gx) + sizeof(sgx_pubkey->gy) + 1;
		pubkey = new uint8_t[pubkey_size]();

		uint8_t *tmp_gx = new uint8_t[sizeof(sgx_pubkey->gx)]();
		uint8_t *tmp_gy = new uint8_t[sizeof(sgx_pubkey->gy)]();

		memcpy(tmp_gx, sgx_pubkey->gx, sizeof(sgx_pubkey->gx));
		memcpy(tmp_gy, sgx_pubkey->gy, sizeof(sgx_pubkey->gy));

		std::reverse(tmp_gx, tmp_gx + sizeof(sgx_pubkey->gx));
		std::reverse(tmp_gy, tmp_gy + sizeof(sgx_pubkey->gy));

		pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;
		memcpy(&pubkey[1], tmp_gx, sizeof(sgx_pubkey->gx));
		memcpy(&pubkey[1 + sizeof(sgx_pubkey->gx)], tmp_gy, sizeof(sgx_pubkey->gy));

		delete[] tmp_gx;
		delete[] tmp_gy;

		BIO_dump_fp(stdout, pubkey, pubkey_size);

		if(!OSSL_PARAM_BLD_push_octet_string(
			param_bld, "pub", pubkey, pubkey_size))
				throw std::exception();

		params = OSSL_PARAM_BLD_to_param(param_bld);
		if(params == NULL) throw std::exception();
		
		if(EVP_PKEY_fromdata(pkey_ctx, &pkey, 
			EVP_PKEY_PUBLIC_KEY, params) <= 0)
				throw std::exception();
	}
	catch(...)
	{
		EVP_PKEY_free(pkey);
	}

	if(pubkey != NULL) delete[] pubkey;
	if(bn_gx != NULL) BN_free(bn_gx);
	if(bn_gy != NULL) BN_free(bn_gy);
	if(pkey_ctx != NULL) EVP_PKEY_CTX_free(pkey_ctx);
	if(params != NULL) OSSL_PARAM_free(params);
	if(param_bld != NULL) OSSL_PARAM_BLD_free(param_bld);

	return pkey;
}

/* uint8_tバイト列（配列）からEVP_PKEY秘密鍵に変換 */
EVP_PKEY* evp_private_key_from_bytes(const uint8_t buf[32])
{
	EVP_PKEY_CTX *pkey_ctx;
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM_BLD *param_bld;
	OSSL_PARAM *params = NULL;
	BIGNUM *bn_priv = NULL;
	int error_flag = 0;

	try
	{
		param_bld = OSSL_PARAM_BLD_new();
		if(param_bld == NULL) throw std::exception();

		if(!OSSL_PARAM_BLD_push_utf8_string(param_bld, 
			OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0))
				throw std::exception();

		pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if(pkey_ctx == NULL) throw std::exception();

		if(EVP_PKEY_fromdata_init(pkey_ctx) <= 0)
			throw std::exception();

		bn_priv = BN_bin2bn(buf, 32, NULL);
		if(bn_priv == NULL) throw std::exception();

		if(!OSSL_PARAM_BLD_push_BN(
			param_bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv))
				throw std::exception();

		params = OSSL_PARAM_BLD_to_param(param_bld);
		if(params == NULL) throw std::exception();
		
		if(EVP_PKEY_fromdata(pkey_ctx, &pkey, 
			EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params) <= 0)
				throw std::exception();
	}
	catch(...)
	{
		EVP_PKEY_free(pkey);
	}

	if(bn_priv != NULL) BN_free(bn_priv);
	if(pkey_ctx != NULL) EVP_PKEY_CTX_free(pkey_ctx);
	if(params != NULL) OSSL_PARAM_free(params);
	if(param_bld != NULL) OSSL_PARAM_BLD_free(param_bld);

	return pkey;
}


/* 128bit AES-CMACを取得 */
int aes_128bit_cmac(uint8_t key[16],
	uint8_t *message, size_t message_len, uint8_t mac[16])
{
	OSSL_LIB_CTX *lib_ctx = NULL;
	EVP_MAC *evp_mac = NULL;
	EVP_MAC_CTX *mac_ctx = NULL;
	size_t mac_len;
	OSSL_PARAM params[2];
	int return_flag = 0;

	try
	{
		evp_mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
		if(evp_mac == NULL) throw std::exception();

		mac_ctx = EVP_MAC_CTX_new(evp_mac);
		if(mac_ctx == NULL) throw std::exception();

		std::string cipher_name = "AES-128-CBC";

		params[0] = OSSL_PARAM_construct_utf8_string(
			OSSL_MAC_PARAM_CIPHER, (char*)cipher_name.c_str(), 0);
		params[1] = OSSL_PARAM_construct_end();

		if(!EVP_MAC_init(mac_ctx, key, 16, params))
			throw std::exception();

		if(!EVP_MAC_update(mac_ctx, message, message_len))
			throw std::exception();

		if(!EVP_MAC_final(mac_ctx, NULL, &mac_len, 0))
			throw std::exception();

		if(mac_len != 16) throw std::exception();

		if(!EVP_MAC_final(mac_ctx, mac, &mac_len, mac_len))
			throw std::exception();

	}
	catch(...)
	{
		return_flag = 1;
	}

	
	if(lib_ctx != NULL) OSSL_LIB_CTX_free(lib_ctx);
	if(mac_ctx != NULL) EVP_MAC_CTX_free(mac_ctx);
	if(evp_mac != NULL) EVP_MAC_free(evp_mac);

	return return_flag;
}


/* SHA-256ハッシュを取得 */
int sha256_digest(const uint8_t *message, size_t message_len, uint8_t digest[32])
{
	EVP_MD_CTX *md_ctx;
	int error_flag = 0;
	memset(digest, 0, 32);

	do
	{
		md_ctx = EVP_MD_CTX_new();
		if(md_ctx == NULL)
		{
			error_flag = 1;
			break;
		}

		if(EVP_DigestInit(md_ctx, EVP_sha256()) != 1)
		{
			error_flag = 1;
			break;
		}

		if(EVP_DigestUpdate(md_ctx, message, message_len) != 1)
		{
			error_flag = 1;
			break;
		}

		if(EVP_DigestFinal(md_ctx, digest, NULL) != 1)
		{
			error_flag = 1;
			break;
		}

	} while(false);

	if(md_ctx != NULL) EVP_MD_CTX_destroy(md_ctx);

	return error_flag;
}


/* ECDSA署名 */
int ecdsa_sign(uint8_t *message, size_t message_len,
	EVP_PKEY *pkey, uint8_t r[32], uint8_t s[32])
{
	EVP_MD_CTX *md_ctx = NULL;
	uint8_t *signature;
	size_t sig_len = 0;
	int error_flag = 0;

	try
	{
		md_ctx = EVP_MD_CTX_new();
		if(md_ctx == NULL) throw std::exception();

		if(!EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey))
			throw std::exception();

		if(!EVP_DigestSignUpdate(md_ctx, message, message_len))
			throw std::exception();

		if(!EVP_DigestSignFinal(md_ctx, NULL, &sig_len))
			throw std::exception();

		if(sig_len <= 0) throw std::exception();

		signature = (uint8_t*)OPENSSL_malloc(sig_len);
		if(signature == NULL) throw std::exception();

		if(!EVP_DigestSignFinal(md_ctx, signature, &sig_len))
			throw std::exception();

		BIO_dump_fp(stdout, signature, sig_len);

		/* 上記出力結果はASN.1形式であるため、生の署名値r,sに変換する */
		const uint8_t *sig_ptr = signature;
		ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(NULL, 
			&sig_ptr, sig_len);

		if(ecdsa_sig == NULL) throw std::exception();

		const BIGNUM *bn_r = NULL;
		const BIGNUM *bn_s = NULL;

		ECDSA_SIG_get0(ecdsa_sig, &bn_r, &bn_s);

		if(!BN_bn2binpad(bn_r, r, 32)) throw std::exception();
		if(!BN_bn2binpad(bn_s, s, 32)) throw std::exception();
	}
	catch(...)
	{
		error_flag = 1;
	}

	if(!error_flag) OPENSSL_free(signature);
	if(md_ctx != NULL) EVP_MD_CTX_free(md_ctx);

	return error_flag;
}


/* X509証明書読み込み処理のラッパー関数 */
int cert_load(X509 **cert, const char *pem_data)
{
	return cert_load_size(cert, pem_data, strlen(pem_data));
}


/* X509証明書の読み込みを実行 */
int cert_load_size(X509 **cert, const char *pem_data, size_t size)
{
	BIO *bio_mem;
	int error_flag = 1; //0ならエラー

	do
	{
		bio_mem = BIO_new(BIO_s_mem());
		if(bio_mem == NULL)
		{
			error_flag = 1;
			break;
		}

		if(BIO_write(bio_mem, pem_data, (int)size) != (int)size)
		{
			error_flag = 1;
			break;
		}

		*cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
		if(*cert == NULL) error_flag = 1;

	} while(false);

	if(bio_mem != NULL) BIO_free(bio_mem);

	return error_flag;
}


/* ファイルから証明書を読み込み */
int cert_load_file(X509 **cert, const char *filename)
{
	FILE *fp;

	if((fp = fopen(filename, "r")) == NULL)
	{
		return 0; //エラー
	}

	*cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if(*cert == NULL) return 0;

	return 1;
}


/* IASのルートCA証明書で証明書ストアを初期化 */
X509_STORE* cert_init_ca(X509 *cert)
{
	X509_STORE *store;

	store = X509_STORE_new();
	if(store == NULL) return NULL;

	if(X509_STORE_add_cert(store, cert) != 1)
	{
		X509_STORE_free(store);
		return NULL;
	}

	return store;
}


/* X509スタックをOpenSSLのSTACK_OF型に変換 */
STACK_OF(X509)* cert_stack_build(X509 **certs)
{
	X509 **cert_ptr;
	STACK_OF(X509) *stack;

	stack = sk_X509_new_null();
	if(stack == NULL) return NULL;

	for(cert_ptr = certs; *cert_ptr != NULL; ++cert_ptr)
	{
		sk_X509_push(stack, *cert_ptr);
	}

	return stack;
}


int cert_verify(X509_STORE *store, STACK_OF(X509) *chain)
{
	X509_STORE_CTX *context;
	X509 *cert = sk_X509_value(chain, 0);
	int error_flag = 1; //0ならエラー

	context = X509_STORE_CTX_new();
	if(context == NULL)
	{
		error_flag = 0;
		return 0;
	}

	do
	{
		if(X509_STORE_CTX_init(context, store, cert, chain) != 1)
		{
			error_flag = 0;
			break;
		}

		if(X509_verify_cert(context) != 1) error_flag = 0;

	} while(false);

	if(context != NULL) X509_STORE_CTX_free(context);

	return error_flag;
}


/* 電子署名の検証を実行 */
int sha256_verify(const uint8_t *msg, size_t msg_len,
    uint8_t *sig, size_t sig_size, EVP_PKEY *pkey, int *result)
{
	EVP_MD_CTX *context;
	int error_flag = 0; //1ならエラー
	
	do
	{
		context = EVP_MD_CTX_new();

		if(context == NULL)
		{
			error_flag = 1;
			break;
		}

		if(EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, pkey) != 1)
		{
			error_flag = 1;
			break;
		}

		if(EVP_DigestVerifyUpdate(context, msg, msg_len) != 1)
		{
			error_flag = 1;
			break;
		}

		if(EVP_DigestVerifyFinal(context, sig, sig_size) != 1) error_flag = 1;

	} while(false);

	if(context != NULL) EVP_MD_CTX_free(context);
	
	return error_flag;
}


/* 証明書チェーンのスタックを解放 */
void cert_stack_free(STACK_OF(X509) *chain)
{
	sk_X509_free(chain);
}