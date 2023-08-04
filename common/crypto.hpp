#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sgx_key_exchange.h>

void crypto_init();

EVP_PKEY* evp_pkey_generate();
uint8_t* derive_shared_secret(EVP_PKEY *Ga, EVP_PKEY *Gb, size_t &secret_len);

int evp_pubkey_to_sgx_ec256(sgx_ec256_public_t *sgx_pubkey, EVP_PKEY *pkey);
EVP_PKEY* evp_pubkey_from_sgx_ec256(sgx_ec256_public_t *sgx_pubkey);
EVP_PKEY* evp_private_key_from_bytes(const uint8_t buf[32]);

int aes_128bit_cmac(uint8_t key[16],
	uint8_t *message, size_t message_len, uint8_t mac[16]);
int sha256_digest(const uint8_t *message, size_t message_len, uint8_t digest[32]);
int ecdsa_sign(uint8_t *message, size_t message_len,
	EVP_PKEY *pkey, uint8_t r[32], uint8_t s[32], uint8_t digest[32]);

int cert_load(X509 **cert, const char *pem_data);
int cert_load_size(X509 **cert, const char *pem_data, size_t sz);
int cert_load_file(X509 **cert, const char *filename);

X509_STORE* cert_init_ca(X509 *cert);
STACK_OF(X509)* cert_stack_build(X509 **certs);
int cert_verify(X509_STORE *store, STACK_OF(X509) *chain);

int sha256_verify(const uint8_t *msg, size_t msg_len,
    uint8_t *sig, size_t sig_size, EVP_PKEY *pkey, int *result);
void cert_stack_free (STACK_OF(X509) *chain);