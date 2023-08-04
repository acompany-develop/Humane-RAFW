#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <string>
#include <exception>

#include "crypto.hpp"
#include "ias_communication.hpp"
#include "base64.hpp"
#include "hexutil.hpp"
#include "debug_print.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../include/httplib.h"

using namespace httplib;


IAS_Communication::IAS_Communication(int server_index,
    char *primary_subscription_key, char *secondary_subscription_key)
{
    this->server_url = "https://api.trustedservices.intel.com";
    this->server_index = server_index;
    this->api_version = IAS_API_DEF_VERSION;
    this->server_port = IAS_PORT;
    this->store = NULL;

    /* 第1引数は0でプライマリ、1でセカンダリを指定する */
    set_subscription_key(0, primary_subscription_key);
    set_subscription_key(1, secondary_subscription_key);
}


IAS_Communication::~IAS_Communication()
{

}


int IAS_Communication::set_subscription_key(int key_type, char *subscription_key)
{
    if(key_type == 0) //プライマリの場合
    {
        memset(primary_subscription_key, 0, sizeof(primary_subscription_key));
        memset(rn_for_xor[0], 0, sizeof(rn_for_xor[0]));
    }
    else if(key_type == 1) //セカンダリの場合
    {
        memset(secondary_subscription_key, 0, sizeof(secondary_subscription_key));
        memset(rn_for_xor[1], 0, sizeof(rn_for_xor[1]));
    }
    else
    {
        std::string message = "Invalid subscription key type.";
        print_debug_message(message, ERROR);
        return 0;
    }

    /* サブスクリプションキーは16進数で32文字でなければならない */
    if(subscription_key == NULL || (strlen(subscription_key) != IAS_SUBSCRIPTION_KEY_SIZE))
    {
        std::string message = "Invalid subscription key format.";
        print_debug_message(message, ERROR);
        return 0;
    }

    if(!key_type)
    {
        /* ワンタイムパッドを乱数的に生成 */
        RAND_bytes((uint8_t*)rn_for_xor[0], (int)sizeof(rn_for_xor[0]));
        
        /* バーナム暗号化によりUntrustedメモリ上で簡易的に保護する */
        for(int i = 0; i < IAS_SUBSCRIPTION_KEY_SIZE; i++)
        {
            primary_subscription_key[i] = (uint8_t) subscription_key[i] ^ rn_for_xor[0][i];
        }
    }
    else
    {
        RAND_bytes((uint8_t*)rn_for_xor[1], (int)sizeof(rn_for_xor[1]));

        for(int i = 0; i < IAS_SUBSCRIPTION_KEY_SIZE; i++)
        {
            secondary_subscription_key[i] = (uint8_t) subscription_key[i] ^ rn_for_xor[1][i];
        }
    }

    memset(subscription_key, 0, IAS_SUBSCRIPTION_KEY_SIZE);

    return 1;
}


std::string IAS_Communication::get_subscription_key()
{
    char plain_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
    memset(plain_key, 0, IAS_SUBSCRIPTION_KEY_SIZE + 1);

    if(!is_primary_failed)
    {
        for(int i = 0; i < IAS_SUBSCRIPTION_KEY_SIZE; i++)
        {
            /* バーナム暗号の復号 */
            plain_key[i] = (primary_subscription_key[i] ^ rn_for_xor[0][i]);
        }
    }
    else
    {
        for(int i = 0; i < IAS_SUBSCRIPTION_KEY_SIZE; i++)
        {
            plain_key[i] = (secondary_subscription_key[i] ^ rn_for_xor[1][i]);
        }
    }

    std::string plain_key_str(plain_key);

    return plain_key;
}


/* ドメイン以下APIバージョン以上の部分を取得する関数 */
std::string IAS_Communication::get_url_parts()
{
    std::string url_parts;

    if(!this->server_index) url_parts += "/sgx/dev";
    else url_parts += "/sgx";

    url_parts += "/attestation/v";

    return url_parts;
}


uint32_t IAS_Communication::sigrl(uint32_t gid, std::string &sigrl)
{
    char gid_buf[9];
    std::string url_parts = this->get_url_parts();

    snprintf(gid_buf, 9, "%08x", gid);

    url_parts += std::to_string(this->api_version);
    url_parts += "/sigrl/";
    url_parts += gid_buf;

    std::string message = "IAS SigRL HTTP Request: ";
    print_debug_message(message, DEBUG_LOG);
    print_debug_message(this->server_url + url_parts, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    Client client(this->server_url);
    Headers header = {
        {"Ocp-Apim-Subscription-Key", this->get_subscription_key()}
    };
    client.set_ca_cert_path("./ca-certificates.crt");

    auto res = client.Get(url_parts, header);

    if(res->status == 200)
    {
        sigrl = res->body;
    }

    return res->status;
}


uint32_t IAS_Communication::report(
    std::map<std::string, std::string> &payload,
        std::string &content)
{
    std::map<std::string, std::string>::iterator itr_map;
    std::string url_parts = this->get_url_parts();
    std::string cert_chain;
    std::string body = "{\n";
    std::vector<X509*> cert_vec;
    X509 **cert_array;
    X509 *sign_cert;
    STACK_OF(X509) *stack;
    std::string sig_str;
    uint32_t status;
    int retval;
    uint8_t *sig = NULL;
    EVP_PKEY *pkey = NULL;

    try
    {
        for(itr_map = payload.begin(); itr_map != payload.end(); ++itr_map)
        {
            if(itr_map != payload.begin())
            {
                body.append(",\n");
            }

            body.append("\"");
            body.append(itr_map->first);
            body.append("\":\"");
            body.append(itr_map->second);
			body.append("\"");
        }

        body.append("\n}");

        url_parts += std::to_string(this->api_version);
        url_parts += "/report";
    }
    catch(...)
    {
        return IAS_STATUS_QUERY_FAILED;
    }

    /* IASへのリクエストを実行 */
    Client client(this->server_url);
    Headers headers = {
        //{"Content-Type", "application/json"},
        {"Ocp-Apim-Subscription-Key", this->get_subscription_key()}
    };
    client.set_ca_cert_path("./ca-certificates.crt");

    auto res = client.Post(url_parts, headers, body, "application/json");

    if(res->status != IAS_STATUS_OK)
    {
        return res->status;
    }

    /* IASからの応答を使用し、アテステーションレポートの検証を行う。検証手順は以下の通り：
     * 1. IASのCAにより発行されている事を確かめるため、証明書チェーンを検証する。
     * 2. 署名証明書から公開鍵を抽出し、署名の検証を行う。 */
    
    cert_chain = res->get_header_value("X-IASReport-Signing-Certificate");

    if(cert_chain == "")
    {
        std::string message = "Header X-IASReport-Signing-Certificate not found.";
        print_debug_message(message, ERROR);
        return IAS_STATUS_BAD_CERTIFICATE;
    }

    /* 証明書チェーンをスタックに格納していく */
    size_t chain_start = 0, chain_end = 0;

    while(chain_end != std::string::npos)
    {
        X509 *cert;
        size_t len;

        chain_end = cert_chain.find("-----BEGIN", chain_start + 1);

        if(chain_end == std::string::npos)
        {
            len = cert_chain.length() - chain_start;
        }
        else
        {
            len = chain_end - chain_start;
        }

        if(!cert_load(&cert, cert_chain.substr(chain_start, len).c_str()))
        {
            std::string message = "Failed to load cert.";
            print_debug_message(message, ERROR);
            return IAS_STATUS_BAD_CERTIFICATE;
        }

        cert_vec.emplace_back(cert);
        chain_start = chain_end;
    }

    size_t count = cert_vec.size();
    cert_array = (X509**)malloc(sizeof(X509*) * (count + 1));

    if(cert_array == 0)
    {
        std::string message = "Failed to malloc for cert array.";
        print_debug_message(message, ERROR);
        return IAS_STATUS_INTERNAL_ERROR;
    }

    for(int i = 0; i < count; i++)
    {
        cert_array[i] = cert_vec[i];
    }
    cert_array[count] = NULL;

    do
    {
        /* スタックをOpenSSLのSTACK_OF(X509)型に変換 */
        stack = cert_stack_build(cert_array);
        if(stack == NULL)
        {
            std::string message = "Failed to build cert stack.";
            print_debug_message(message, ERROR);
            status = IAS_STATUS_INTERNAL_ERROR;
            break;
        }

        /* IASのルートCA証明書を用いて検証を実行する */
        int retval = cert_verify(this->get_cert_store(), stack);

        if(!retval)
        {
            std::string message = "Certificate verification failure.";
            print_debug_message(message, ERROR);
            status = IAS_STATUS_BAD_CERTIFICATE;
            break;
        }

        /* Attestation応答に対する署名をヘッダから抽出 */
        sig_str = res->get_header_value("X-IASReport-Signature");
        if(sig_str == "")
        {
            std::string message = "Header X-IASReport-Signature not found.";
            status = IAS_STATUS_BAD_SIGNATURE;
            break;
        }

        size_t sig_size;
        sig = base64_decode<uint8_t, char>((char*)sig_str.c_str(), sig_size);

        if(sig == NULL)
        {
            std::string message = "Failed to decode signature from base64.";
            print_debug_message(message, ERROR);
            status = IAS_STATUS_BAD_SIGNATURE;
            break;
        }

        sign_cert = cert_vec[0];

        /* REPORT構造体のBodyであるAttestation応答に対する署名（SHA256ハッシュ）の
         * 検証のため、公開鍵を証明書から抽出する */
        pkey = X509_get_pubkey(sign_cert);
        
        if(pkey == NULL)
        {
            std::string message = "Failed to extract public key from cert.";
            print_debug_message(message, ERROR);
            status = IAS_STATUS_INTERNAL_ERROR;
            break;
        }

        /* Attestation応答を抽出 */
        content = res->body;

        /* Attestation応答のハッシュ値、公開鍵、署名を用いて署名検証を実施 */
        if(sha256_verify((const uint8_t*)content.c_str(), 
            content.length(), sig, sig_size, pkey, &retval))
        {
            std::string message = "Could not validate signature.";
            print_debug_message(message, ERROR);
            status = IAS_STATUS_BAD_SIGNATURE;
        }
        else
        {
            if(retval)
            {
                status = IAS_STATUS_OK;
            }
            else
            {
                std::string message = "Invalid report signature.";
                print_debug_message(message, ERROR);
                status = IAS_STATUS_BAD_SIGNATURE;
            }
        }

    } while(false);

    if(pkey != NULL) EVP_PKEY_free(pkey);
    cert_stack_free(stack);
    free(cert_array);
    for(int i = 0; i < count; i++) X509_free(cert_vec[i]);
    free(sig);

    return status;
}