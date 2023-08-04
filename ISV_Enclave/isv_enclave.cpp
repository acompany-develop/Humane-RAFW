#include "isv_enclave_t.h"
#include <sgx_utils.h>
#include <sgx_trts.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include "../common/debug_print.hpp"


/* 署名・検証で使用するSPの256bit ECDSA公開鍵。
 * RAによるTLS確立前に改竄や中間者攻撃などが実行されるのを防ぐため、
 * ハードコーディングしておく必要がある。
 * RA中にランダムに生成する鍵Gbとは別物。 
 */
static const sgx_ec256_public_t service_provider_public_key = {
    {
        0x7b, 0xee, 0x75, 0x24, 0x1b, 0x84, 0x69, 0x58,
        0x6e, 0x1d, 0x65, 0xbd, 0x3e, 0x2e, 0x5e, 0xf1,
        0x33, 0x08, 0x34, 0x11, 0xf0, 0x58, 0xe1, 0x34,
        0x48, 0x05, 0xea, 0x73, 0xaf, 0xbc, 0x96, 0x0c
    },
    {
        0xf2, 0x43, 0x3d, 0x5b, 0xfe, 0x53, 0x22, 0x4c,
        0xc0, 0x41, 0xd1, 0xf4, 0x34, 0x66, 0xb8, 0x5e,
        0x65, 0x05, 0x5d, 0xad, 0x85, 0x6e, 0x22, 0xa7,
        0x8c, 0xe1, 0x91, 0x80, 0xd1, 0xfd, 0x3e, 0x1a
    }
};


/* RAを初期化しsgx_ra_context_tを取得。
 * LinuxではPSEは使用不可なのでそもそもコーディングに含めない。
 * SPが複数存在する場合は、公開鍵識別用の機構を別途実装する必要がある */
sgx_status_t ecall_ra_init(sgx_ra_context_t *ra_ctx)
{
    sgx_status_t status;
    status = sgx_ra_init(&service_provider_public_key, 0, ra_ctx);

    return status;
}


/* RAの終了処理を行う */
sgx_status_t ecall_ra_close(sgx_ra_context_t ra_ctx)
{
    sgx_status_t status = sgx_ra_close(ra_ctx);
    return status;
}


sgx_status_t ecall_sample_addition(sgx_ra_context_t ra_ctx,
    uint8_t *cipher1, size_t cipher1_len, uint8_t *cipher2,
    size_t cipher2_len, uint8_t *iv, uint8_t *tag1, 
    uint8_t *tag2, uint8_t *result, size_t *result_len,
    uint8_t *iv_result, uint8_t *tag_result)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_ra_key_128_t sk_key, mk_key;

    status = sgx_ra_get_keys(ra_ctx, SGX_RA_KEY_SK, &sk_key);
    status = sgx_ra_get_keys(ra_ctx, SGX_RA_KEY_MK, &mk_key);

    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to get session key.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    if(cipher1_len > 32 || cipher2_len > 32)
    {
        const char *message = "The cipher size is too large.";
        ocall_print(message, 2);
        status = SGX_ERROR_INVALID_PARAMETER;
        return status;
    }

    /* GCMでは暗号文と平文の長さが同一 */
    uint8_t *plain_1 = new uint8_t[cipher1_len]();
    uint8_t *plain_2 = new uint8_t[cipher2_len]();

    /* GCM復号 */
    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher1,
        cipher1_len, plain_1, iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)tag1);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt cipher1.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher2,
        cipher2_len, plain_2, iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)tag2);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt cipher2.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    uint64_t num1 = atol((const char*)plain_1);
    uint64_t num2 = atol((const char*)plain_2);

    /* 加算を実行 */
    uint64_t total = num1 + num2;

    /* 返信用に暗号化を実施 */
    std::string total_str = std::to_string(total);
    uint8_t *total_u8 = (uint8_t*)total_str.c_str();
    
    *result_len = total_str.length();

    /* "32"はEnclave外で決め打ちで確保しているバッファ数 */
    if(*result_len > 32)
    {
        const char *message = "The result cipher size is too large.";
        ocall_print(message, 2);
        status = SGX_ERROR_INVALID_PARAMETER;
        return status;
    }

    /* RDRANDで真性乱数的にIVを生成 */
    status = sgx_read_rand(iv_result, 12);

    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to generate IV inside enclave.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    /* 計算結果をGCMで暗号化 */
    status = sgx_rijndael128GCM_encrypt(&mk_key, 
        total_u8, *result_len, result, iv_result, 12,
        NULL, 0, (sgx_aes_gcm_128bit_tag_t*)tag_result);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to encrypt result.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    delete plain_1;
    delete plain_2;

    return status;
}