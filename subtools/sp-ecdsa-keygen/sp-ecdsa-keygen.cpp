#include <openssl/cmac.h>
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
#include "../../common/crypto.hpp"


/* 秘密鍵をuint8_t配列に変換 */
int evp_prvkey_to_u8(uint8_t (&u_prvkey)[32], EVP_PKEY *pkey)
{
	BIGNUM *bn_prvkey = NULL;
	EC_KEY *ec_key = NULL;

	ec_key = EVP_PKEY_get1_EC_KEY(pkey);
	if(ec_key == NULL)
	{
		BN_free(bn_prvkey);
		return -1;
	}

	bn_prvkey = (BIGNUM*)EC_KEY_get0_private_key(ec_key);

	if(!BN_bn2bin(bn_prvkey, u_prvkey))
	{
		BN_free(bn_prvkey);
		return -1;
	}

	BN_free(bn_prvkey);

	return 0;
}


void print_u8_pubkey(uint8_t gx[32], uint8_t gy[32])
{
	std::cout << "\n\nCopy the following public keys and hardcode them into " 
				<< "ISV's Enclave code (ex: isv_enclave.cpp):\n" << std::endl;

	printf("\t{\n");
	int index = 0;

	for (int i = 0; i < 4; i++)
	{
		printf("\t\t");
		for(int j = 0; j < 8; j++)
		{
			printf("0x");
			printf("%02x", (uint8_t)gx[index]);
			if(index != 31) printf(",");
			if(j < 7) printf(" ");
			index++;
		}
		printf("\n");
	}

	printf("\t},\n\t{\n");
	index = 0;

	for (int i = 0; i < 4; i++)
	{
		printf("\t\t");
		for(int j = 0; j < 8; j++)
		{
			printf("0x");
			printf("%02x", (uint8_t)gy[index]);
			if(index != 31) printf(",");
			if(j < 7) printf(" ");
			index++;
		}
		printf("\n");
	}

	printf("\t}");
	index = 0;

	std::cout << "\n" << std::endl;
}


void print_u8_prvkey(uint8_t prvkey[32])
{
	std::cout << "\n\nCopy the following private key and hardcode it into " 
				<< "SP's untrusted code (ex: sp_app.cpp):\n" << std::endl;

	int index = 0;

	for (int i = 0; i < 4; i++)
	{
		printf("\t");
		for(int j = 0; j < 8; j++)
		{
			printf("0x");
			printf("%02x", (uint8_t)prvkey[index]);
			if(index != 31) printf(",");
			if(j < 7) printf(" ");
			index++;
		}
		printf("\n");
	}

	std::cout << "\n" << std::endl;
}



int main()
{
    EVP_PKEY *pkey= NULL;

	/* キーペアを生成 */
    pkey = evp_pkey_generate();

    /* デバッグ用表示 */
	std::cout << "---------------- DEBUG MESSAGE START ----------------" << std::endl;
    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(out, pkey, 0, NULL);

	/* 公開鍵をsgx_ec256_public_tに変換(リトルエンディアン化) */
	sgx_ec256_public_t sgx_pubkey;
    if(evp_pubkey_to_sgx_ec256(&sgx_pubkey, pkey) != 0)
	{
		std::cerr << "Failed to convert pubkey to sgx_ec256_public_t." << std::endl;
		return 0;
	}
	
	/* 秘密鍵をuint8_t配列に変換 */
	uint8_t u_prvkey[32];
	if(evp_prvkey_to_u8(u_prvkey, pkey) != 0)
	{
		std::cerr << "Failed to convert private key to uint8_t array." << std::endl;
		return 0;
	}

	std::cout << "\n\nlittle-endianed gx->" << std::endl;
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", (uint8_t) sgx_pubkey.gx[i]);
	}

	std::cout << "\nlittle-endianed gy->" << std::endl;
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", (uint8_t) sgx_pubkey.gy[i]);
	}

	std::cout << "\nbig-endianed private key->" << std::endl;
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", (uint8_t) u_prvkey[i]);
	}
	std::cout << std::endl;
		std::cout << "---------------- DEBUG MESSAGE END ------------------" << std::endl;

	print_u8_pubkey(sgx_pubkey.gx, sgx_pubkey.gy);
	print_u8_prvkey(u_prvkey);

	return 0;
}