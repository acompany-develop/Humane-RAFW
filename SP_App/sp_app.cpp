#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>
#include <algorithm>
#include <string.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../include/httplib.h"
#include "../include/ini.h"
#include "../include/json.hpp"
#include "../common/base64.hpp"
#include "../common/ias_communication.hpp"
#include "../common/debug_print.hpp"
#include "../common/hexutil.hpp"
#include "../common/crypto.hpp"
#include "../common/attestation_status.hpp"

using namespace httplib;


/* 署名・検証で使用するSPの256bit ECDSA秘密鍵。
 * RA中にランダムに生成する鍵Gbとは別物。 */
static const uint8_t service_provider_private_key[32] = {
    0x2a, 0x28, 0x03, 0x26, 0x1f, 0xb4, 0x5a, 0x96,
    0x51, 0xad, 0xaa, 0xa7, 0xe8, 0x76, 0x43, 0x36,
    0x8f, 0x64, 0xab, 0xa4, 0xa1, 0x69, 0xff, 0xe6,
    0x15, 0x50, 0x09, 0x10, 0x5d, 0x6d, 0x4d, 0xfa
};


/* RAセッション中に発生する鍵関係コンテキスト用構造体 */
typedef struct sp_ra_session_struct
{
    uint8_t g_a[64];
    uint8_t g_b[64];
    uint8_t kdk[64];
    uint8_t smk[16];
    uint8_t vk[16];
    uint8_t sk[16];
    uint8_t mk[16];
} sp_ra_session_t;


/* 設定ファイルから読み込んだ内容を格納 */
typedef struct sp_config_struct
{
    sgx_spid_t spid;
    uint8_t primary_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
    uint8_t secondary_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
    uint16_t quote_type;
    EVP_PKEY *service_private_key;
    X509_STORE *store;
    X509 *signing_ca;
    sgx_measurement_t req_mrenclave;
    sgx_measurement_t req_mrsigner;
    sgx_prod_id_t req_isv_prod_id;
    sgx_isv_svn_t min_isv_svn;
    bool skip_mrenclave_check;
} sp_config_t;


/* iniファイルから読み込み、失敗時にはプログラムを即時終了する */
std::string load_from_ini(std::string section, std::string key)
{
    mINI::INIFile file("settings.ini");
    mINI::INIStructure ini;

    if(!file.read(ini))
    {
        std::string message = "file read error";
        print_debug_message(message, ERROR);
        exit(1);
    }
    std::string ret = ini.get(section).get(key);

    if(ret.length() == 0)
    {
        std::string message = "Failed to load setting " + key + " from settings.ini.";
        print_debug_message(message, ERROR);
        exit(1); 
    }

    return ret;
}


/* settings.iniからの設定情報の読み込み */
int load_settings(sp_config_t &config)
{
    /* iniパーサを用いて各設定を一旦string型で読み込む */
    std::string spid_str = load_from_ini("sp", "SPID");
    std::string linkable_str = load_from_ini("sp", "LINKABLE");
    std::string primary_key_str = load_from_ini("sp", "IAS_PRIMARY_SUBSCRIPTION_KEY");
    std::string secondary_key_str = load_from_ini("sp", "IAS_SECONDARY_SUBSCRIPTION_KEY");
    std::string ias_cert_file_str = load_from_ini("sp", "IAS_REPORT_SIGNING_CA_FILE");
    std::string isvsvn_str = load_from_ini("sp", "MINIMUM_ISVSVN");
    std::string isv_prodid_str = load_from_ini("sp", "REQUIRED_ISV_PROD_ID");
    std::string mrenclave_str = load_from_ini("sp", "REQUIRED_MRENCLAVE");
    std::string mrsigner_str = load_from_ini("sp", "REQUIRED_MRSIGNER");
    std::string skip_mrenclave_check_str = load_from_ini("sp", "SKIP_MRENCLAVE_CHECK");


    /* SPIDをHexから変換して格納 */
    std::string spid_lowercase_str;
    spid_lowercase_str.resize(spid_str.size());
    std::transform(spid_str.begin(), spid_str.end(),
                spid_lowercase_str.begin(), tolower);

    const char *spid_char = spid_lowercase_str.c_str();

    if(strlen(spid_char) != 32)
    {
        std::string message = "SPID must be 32 characters in hex.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    uint8_t spid_u8[16];

    int ret = from_hexstring(spid_u8,
            (const void*)spid_char, strlen(spid_char) / 2);

    if(ret)
    {
        std::string message = "Failed to convert hex to uint8_t for SPID.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    for(int i = 0; i < 16; i++)
    {
        config.spid.id[i] = spid_u8[i];
    }

    //BIO_dump_fp(stdout, (char*)config.spid.id, 16);


    /* Linkableフラグを格納 */
    uint32_t linkable = std::stoi(linkable_str);

    if(!(linkable == 0 || linkable == 1))
    {
        std::string message = "Linkable flag must be 0 or 1.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    //0か1であればshort型にキャストしても確定で安全
    config.quote_type = (uint16_t)linkable;


    /* サブスクリプションキーを格納 */
    //プライマリ
    size_t primary_key_len = primary_key_str.length();
    if(primary_key_len != IAS_SUBSCRIPTION_KEY_SIZE)
    {
        std::string message = "Invalid primary subscription key format.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    strcpy((char*)config.primary_key, primary_key_str.c_str());

    //セカンダリ
    size_t secondary_key_len = secondary_key_str.length();
    if(secondary_key_len != IAS_SUBSCRIPTION_KEY_SIZE)
    {
        std::string message = "Invalid secondary subscription key format.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    strcpy((char*)config.secondary_key, secondary_key_str.c_str());


    /* IASのルート証明書を読み込んで証明書ストアを初期化 */
    if(!cert_load_file(&config.signing_ca, ias_cert_file_str.c_str()))
    {
        std::string message = "Failed to load IAS cert file.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    config.store = cert_init_ca(config.signing_ca);
    if(config.store == NULL)
    {
        std::string message = "Failed to initialize certificate store.";
        print_debug_message(message, ERROR);
        exit(1);
    }


    /* ISVに要求する最低SVNを格納 */
    config.min_isv_svn = (sgx_isv_svn_t)std::stoi(isvsvn_str);
    

    /* ISVに要求するProd IDを格納 */
    config.req_isv_prod_id = (sgx_prod_id_t)std::stoi(isv_prodid_str);


    /* 要求するMRENCLAVEをHexから変換して格納 */
    const char *mrenclave_char = mrenclave_str.c_str();

    if(strlen(mrenclave_char) != 64)
    {
        std::string message = "Requiring MRENCLAVE must be 64 characters in hex.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    uint8_t mrenclave_u8[32];

    ret = from_hexstring(mrenclave_u8,
        (const void*)mrenclave_char, strlen(mrenclave_char) / 2);

    if(ret)
    {
        std::string message = "Failed to convert hex to uint8_t for MRENCLAVE.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    for(int i = 0; i < 32; i++)
    {
        config.req_mrenclave.m[i] = mrenclave_u8[i];
    }

    //BIO_dump_fp(stdout, (char*)config.req_mrenclave.m, 32);


    /* 要求するMRSIGNERをHexから変換して格納 */
    const char *mrsigner_char = mrsigner_str.c_str();

    if(strlen(mrsigner_char) != 64)
    {
        std::string message = "Requiring MRSIGNER must be 64 characters in hex.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    uint8_t mrsigner_u8[32];

    ret = from_hexstring(mrsigner_u8,
        (const void*)mrsigner_char, strlen(mrsigner_char) / 2);

    if(ret)
    {
        std::string message = "Failed to convert hex to uint8_t for MRSIGNER.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    for(int i = 0; i < 32; i++)
    {
        config.req_mrsigner.m[i] = mrsigner_u8[i];
    }

    //BIO_dump_fp(stdout, (char*)config.req_mrsigner.m, 32);


    /* MRENCLAVEスキップフラグを格納 */
    uint32_t skip_flag = std::stoi(skip_mrenclave_check_str);

    if(!(skip_flag == 0 || skip_flag == 1))
    {
        std::string message = "MRENCLAVE check skip flag must be 0 or 1.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    config.skip_mrenclave_check = skip_flag;


    /* 署名・検証で使用するSPのハードコーディング秘密鍵を
     * OpenSSLのEVP形式で読み込み */
    config.service_private_key = 
        evp_private_key_from_bytes(service_provider_private_key);

    if(config.service_private_key == NULL)
    {
        std::string message = "Failed to load hardcoded SP private key.";
        print_debug_message(message, ERROR);
        exit(1);
    }
    

    std::string message = "Loading settings from ini file completed.";
    print_debug_message(message, INFO);

    return 0;
}


/* KDK（鍵導出鍵）の導出 */
int generate_kdk(EVP_PKEY *Gb, uint8_t kdk[16],
    sgx_ec256_public_t g_a, sp_config_t &config)
{
    EVP_PKEY *Ga; //ISV側のキーペア（EVP形式）
    uint8_t *Gab_x; //共有秘密
    uint8_t *cmac_key = new uint8_t[16](); //0埋めしてCMACの鍵として使用する
    size_t secret_len;

    /* ISVの鍵をsgx_ec256_public_tからEVP_PKEYに変換 */
    Ga = evp_pubkey_from_sgx_ec256(&g_a);

    if(Ga == NULL)
    {
        std::string message = "Failed to convert Ga from sgx_ec256_public_t.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 共有秘密を導出する */
    Gab_x = derive_shared_secret(Ga, Gb, secret_len);

    if(Gab_x == NULL)
    {
        std::string message = "Failed to derive shared secret.";
        print_debug_message(message, ERROR);
        return -1;
    }

    print_debug_binary("shared secret Gab_x", Gab_x, secret_len, DEBUG_LOG);


    /* 共有秘密をリトルエンディアン化 */
    std::reverse(Gab_x, Gab_x + secret_len);

    print_debug_binary(
        "reversed shared secret Gab_x", Gab_x, secret_len, DEBUG_LOG);


    /* CMAC処理を実行してKDKを導出 */
    aes_128bit_cmac(cmac_key, Gab_x, secret_len, kdk);

    print_debug_binary("KDK", kdk, 16, DEBUG_LOG);

    return 0;
}


/* SigRLをIASから取得する */
int get_sigrl(IAS_Communication *ias, sgx_epid_group_id_t gid, 
    uint8_t* &sigrl, uint32_t &sigrl_size)
{
    int error_flag = 0;

    uint32_t ret = IAS_STATUS_OK;
    std::string sigrl_str;

    while(1)
    {
        /* IASと通信しSigRLを取得する */
        ret = ias->sigrl(*(uint32_t*)gid, sigrl_str);
        print_debug_message(
            "SigRL request status: " + std::to_string(ret), DEBUG_LOG);

        if(ret == IAS_STATUS_UNAUTHORIZED && (ias->get_is_primary_failed() == false))
        {
            print_debug_message(
                "Failed to get SigRL with primary subscryption key.", INFO);
            print_debug_message(
                "Try again with secondary subscription key,", INFO);

            ias->set_is_primary_failed(true);
            continue;     
        }
        else if(ret != IAS_STATUS_OK) return -1;

        break;
    }

    /* 受信したSigRLをBase64デコード */
    size_t size;
    sigrl = base64_decode<uint8_t, char>((char*)sigrl_str.c_str(), size);

    if(sigrl == NULL)
    {
        print_debug_message("Failed to decode SigRL from base64.", ERROR);
        return -1;
    }

    sigrl_size = (uint32_t)size;

    return 0;
}


/* QuoteをIASに送信しRAレポートを取得 */
int get_attestation_report(IAS_Communication *ias, 
    char *quote_b64, ra_msg4_t *msg4)
{
    std::map<std::string, std::string> payload;
    std::string response_json;
    payload.insert(std::make_pair("isvEnclaveQuote", quote_b64));

    /* IASと通信 */
    uint32_t ret = ias->report(payload, response_json);

    if(ret != IAS_STATUS_OK)
    {
        print_debug_message(
            "RA report request Failed: " + std::to_string(ret), ERROR);
        switch(ret)
        {
            case IAS_STATUS_QUERY_FAILED:
                print_debug_message("Failed to query IAS.", ERROR);
                break;

            case IAS_STATUS_BAD_REQUEST:
                print_debug_message("Invalid Quote payload.", ERROR);
                break;

            case IAS_STATUS_UNAUTHORIZED:
                print_debug_message("Failed to authenticate request.", ERROR);
                break;

            case IAS_STATUS_SERVICE_UNAVAILABLE:
                print_debug_message("IAS service is currently unavailable.", ERROR);
                break;

            case IAS_STATUS_SERVER_ERROR:
                print_debug_message("Internal server error at IAS.", ERROR);
                break;

            case IAS_STATUS_BAD_CERTIFICATE:
                print_debug_message("Failed to verify signing cert.", ERROR);
                break;

            case IAS_STATUS_BAD_SIGNATURE:
                print_debug_message("Failed to verify report signature.", ERROR);
                break;

            default:
                if(ret >= 100 && ret < 600)
                {
                    print_debug_message("Unexpected http response code.", ERROR);
                }
                else
                {
                    print_debug_message("Unknown error.", ERROR);
                }
        }

        return -1;
    }

    print_debug_message("==============================================", INFO);
    print_debug_message("Finalize Remote Attestation", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);
    print_debug_message(
        "RA report request status: " + std::to_string(ret), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    json::JSON report_obj = json::JSON::Load(response_json);

    print_debug_message("json -> ", DEBUG_LOG);
    print_debug_message(response_json, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);
    
    /* RA応答の内容を列挙 */
    print_debug_message("id -> ", DEBUG_LOG);
    print_debug_message(report_obj["id"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("timestamp -> ", DEBUG_LOG);
    print_debug_message(report_obj["timestamp"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("version -> ", DEBUG_LOG);
    print_debug_message(std::to_string(report_obj["version"].ToInt()), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("platformInfoBlob -> ", DEBUG_LOG);
    print_debug_message(report_obj["platformInfoBlob"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("revocationReason -> ", DEBUG_LOG);
    print_debug_message(report_obj["revocationReason"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("pseManifestStatus -> ", DEBUG_LOG);
    print_debug_message(report_obj["pesManifestStatus"].ToString(), DEBUG_LOG);

    print_debug_message("pseManifestHash -> ", DEBUG_LOG);
    print_debug_message(report_obj["pseManifestHash"].ToString(), DEBUG_LOG);

    print_debug_message("nonce -> ", DEBUG_LOG);
    print_debug_message(report_obj["nonce"].ToString(), DEBUG_LOG);

    print_debug_message("epidPseudonym -> ", DEBUG_LOG);
    print_debug_message(report_obj["epidPseudonym"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);


    print_debug_message("isvEnclaveQuoteBody -> ", DEBUG_LOG);
    print_debug_message(report_obj["isvEnclaveQuoteBody"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("isvEnclaveQuoteStatus -> ", DEBUG_LOG);
    print_debug_message(report_obj["isvEnclaveQuoteStatus"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("advisoryIDs -> ", DEBUG_LOG);

    for(int i = 0; i < report_obj["advisoryIDs"].length(); i++)
    {
        print_debug_message(
            report_obj["advisoryIDs"][i].ToString(), DEBUG_LOG);
    }

    print_debug_message("", DEBUG_LOG);

    print_debug_message("advisoryURL -> ", DEBUG_LOG);
    print_debug_message(report_obj["advisoryURL"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);


    /* RA応答内のAPIバージョンが期待しているもの(v4)と一致しているか確認 */
    if((uint32_t)IAS_API_DEF_VERSION != 
        (uint32_t)report_obj["version"].ToInt())
    {
        std::string message = 
            "RA report has been returned from unexpected version of IAS-API.";
        print_debug_message(message, ERROR);
        return -1;
    }

    memset(msg4, 0, sizeof(ra_msg4_t));

    print_debug_message(
        "Attestation Status (before check MRENCLAVE, etc.) -> ", INFO);

    std::string ra_status = report_obj["isvEnclaveQuoteStatus"].ToString();

    if(ra_status == "OK")
    {
        msg4->status = Trusted;
        std::string desc = "Enclave Trusted.";
        memcpy(msg4->description, desc.c_str(), desc.length());

        print_debug_message("Enclave Trusted.", INFO);
        print_debug_message("", DEBUG_LOG);
    }
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
    else if(ra_status == "CONFIGURATION_NEEDED")
    {
        msg4->status = Conditionally_Trusted;
        std::string desc = std::string("Deem the Enclave as Trusted, but ISV's ") +
            std::string("hardware should be applied some additional configuration.");
        
        memcpy(msg4->description, desc.c_str(), desc.length());

        print_debug_message(desc, INFO);
        print_debug_message("", DEBUG_LOG);
    }
    else if(ra_status == "GROUP_OUT_OF_DATE")
    {
        msg4->status = NotTrusted;
        std::string desc = std::string("Enclave is not Trusted. ") +
            std::string("ISV's platform should apply some updates.");
        
        memcpy(msg4->description, desc.c_str(), desc.length());

        print_debug_message(desc, INFO);
        print_debug_message("", DEBUG_LOG);
    }
    else
    {
        msg4->status = NotTrusted;
        std::string desc = "Enclave is not Trusted. Reason: ";

        memcpy(msg4->description, desc.c_str(), desc.length());

        print_debug_message(desc, INFO);
        print_debug_message("", DEBUG_LOG);
    }


    /* PIB（Platform Info Blob）がIASから提供されていればmsg4に同梱 */
    if(!report_obj["platformInfoBlob"].IsNull())
    {
        print_debug_message(
            "PIB (Platform Info Blob) is provided by IAS ->", DEBUG_LOG);
        
        std::string pib_str = report_obj["platformInfoBlob"].ToString();

        /* PIBからTLVヘッダ（Base16形式の8バイト）を除去 */
        pib_str.erase(0, 4*2);

        from_hexstring((uint8_t*)&msg4->pib,
            pib_str.c_str(), pib_str.length() / 2);

        print_debug_message(pib_str, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
    }
    else
    {
        print_debug_message(
            "PIB (Platform Info Blob) is not provided by IAS.", DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
        memset(msg4->pib.platform_info, 0, SGX_PLATFORM_INFO_SIZE);
    }

    return 0;
}


/* SPの各要求をISVのEnclaveが満たしているかを検証。
 * ここで要求を満たさない事が発覚した場合、プラットフォームの安全性の議論よりも
 * 重大度が高いため（Enclave改竄等の可能性）、msg4中のdescriptionは
 * 上書きする */
void verify_enclave(ra_msg4_t *msg4,
    sgx_report_body_t *report, sp_config_t config)
{
    print_debug_message(
        "Enclave identity verification-----------------", DEBUG_LOG);

    /* MRENCLAVE */
    print_debug_binary("requested MRENCLAVE",
        (uint8_t*)&config.req_mrenclave, 32, DEBUG_LOG);
    print_debug_binary("received MRENCLAVE",
        (uint8_t*)&report->mr_enclave, 32, DEBUG_LOG);
    
    // SPによりMRENCLAVE検証スキップを指定されていない場合のみ実行
    if(!config.skip_mrenclave_check)
    {
        if(memcmp(&report->mr_enclave, &config.req_mrenclave, 32))
        {
            std::string desc = "MRENCLAVE mismatched.";
            print_debug_message(desc, INFO);
            print_debug_message("", INFO);

            msg4->status = NotTrusted;
            memset(msg4->description, 0, 512);
            memcpy(msg4->description, desc.c_str(), desc.length());
        }
    }

    /* MRSIGNER */
    print_debug_binary("requested MRSIGNER",
        (uint8_t*)&config.req_mrsigner, 32, DEBUG_LOG);
    print_debug_binary("received MRSIGNER",
        (uint8_t*)&report->mr_signer, 32, DEBUG_LOG);
    
    if(memcmp(&report->mr_signer, &config.req_mrsigner, 32))
    {
        std::string desc = "MRSIGNER mismatched.";
        print_debug_message(desc, INFO);
        print_debug_message("", INFO);

        msg4->status = NotTrusted;
        memset(msg4->description, 0, 512);
        memcpy(msg4->description, desc.c_str(), desc.length());
    }

    /* ISVSVN */
    print_debug_message("requested ISVSVN -> ", DEBUG_LOG);
    print_debug_message(std::to_string(config.min_isv_svn), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("received ISVSVN -> ", DEBUG_LOG);
    print_debug_message(std::to_string(report->isv_svn), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    if(report->isv_svn < config.min_isv_svn)
    {
        std::string desc = "Insufficient ISVSVN.";
        print_debug_message(desc, INFO);
        print_debug_message("", INFO);

        msg4->status = NotTrusted;
        memset(msg4->description, 0, 512);
        memcpy(msg4->description, desc.c_str(), desc.length());
    }

    /* ISV ProdID */
    print_debug_message("requested ISV ProdID -> ", DEBUG_LOG);
    print_debug_message(std::to_string(config.req_isv_prod_id), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("received ISV ProdID -> ", DEBUG_LOG);
    print_debug_message(std::to_string(report->isv_prod_id), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    if(report->isv_prod_id != config.req_isv_prod_id)
    {
        std::string desc = "Insufficient ISV ProdID.";
        print_debug_message(desc, INFO);
        print_debug_message("", INFO);

        msg4->status = NotTrusted;
        memset(msg4->description, 0, 512);
        memcpy(msg4->description, desc.c_str(), desc.length());
    }

    return;
}


/* チャレンジリクエストを送信し、msg0を受信する */
int process_msg0(std::string &ra_ctx_b64,
    uint32_t &extended_epid_group_id, std::string isv_url)
{
    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Process msg0", INFO);
    print_debug_message("==============================================", INFO);

    Client client(isv_url);
    auto res = client.Get("/msg0");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably ISV server is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json;
    json::JSON json_obj;

    response_json = res->body;
    json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        char *ra_ctx_char, *ex_epid_gid_char;
        size_t ra_ctx_size, ex_epid_gid_size;

        /* base64形式のRAコンテキストを取得 */
        ra_ctx_b64 = std::string(json_obj["ra_context"].ToString().c_str());

        /* Base64デコード */
        ra_ctx_char = base64_decode<char, char>(
            (char*)json_obj["ra_context"].ToString().c_str(), ra_ctx_size);

        ex_epid_gid_char = base64_decode<char, char>(
            (char*)json_obj["extended_epid_gid"].ToString().c_str(), ex_epid_gid_size);
        
        sgx_ra_context_t ra_ctx = (sgx_ra_context_t)std::stoi(ra_ctx_char);
        extended_epid_group_id = (uint32_t)std::stoi(ex_epid_gid_char);

        std::string message_ra_ctx =
            "Received RA context number -> " + std::to_string(ra_ctx);
        std::string message_ex_epid_gid = 
            "Received extended EPID group ID -> " + std::to_string(extended_epid_group_id);

        print_debug_message(message_ra_ctx, INFO);
        print_debug_message(message_ex_epid_gid, INFO);

        /* 拡張EPID-GIDは現状では必ず0でなければならないと
        * リファレンスに記載されている */
        if(extended_epid_group_id != 0)
        {
            print_debug_message("Invalid Extended EPID-GID. This value must be 0.", ERROR);
            return -1;
        }
    }
    else if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        exit(1);
    }
    else
    {
        std::string message = "Unexpected error while processing msg0.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    return 0;
}


/* msg1を受信しmsg2を作成 */
int process_msg1(std::string &ra_ctx_b64, IAS_Communication *ias,
    sgx_ra_msg1_t &msg1, sgx_ra_msg2_t &msg2, sp_config_t &config,
    sp_ra_session_t &session, std::string isv_url)
{
    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Process msg1", INFO);
    print_debug_message("==============================================", INFO);

    Client client(isv_url);
    json::JSON req_json_obj, res_json_obj;
    std::string request_json;

    req_json_obj["ra_context"] = ra_ctx_b64;
    request_json = req_json_obj.dump();

    /* SP識別用にRAコンテキストを含めてPost */
    auto res = client.Post("/msg1", request_json, "application/json");
    std::string response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else if(res->status != 200)
    {
        std::string message = "Unexpected error while processing msg1.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    uint8_t *g_a_gx, *g_a_gy, *gid;
    size_t gx_size, gy_size, gid_size;

    /* msg1の内容をuint8_t配列に変換 */
    g_a_gx = base64_decode<uint8_t, char>(
        (char*)res_json_obj["msg1"]["g_a"]["gx"].ToString().c_str(), gx_size);
    g_a_gy = base64_decode<uint8_t, char>(
        (char*)res_json_obj["msg1"]["g_a"]["gy"].ToString().c_str(), gy_size);
    gid = base64_decode<uint8_t, char>(
        (char*)res_json_obj["msg1"]["gid"].ToString().c_str(), gid_size);

    for(int i = 0; i < 32; i++)
    {
        msg1.g_a.gx[i] = g_a_gx[i];
        msg1.g_a.gy[i] = g_a_gy[i];
    }

    for(int i = 0; i < 4; i++)
    {
        msg1.gid[i] = gid[i];
    }

    /* msg1の内容をデバッグ表示。まずはキーペア公開鍵x成分 */
    print_debug_binary("msg1.g_a.gx", msg1.g_a.gx, 32, DEBUG_LOG);

    /* キーペア公開鍵y成分 */
    print_debug_binary("msg1.g_a.gy", msg1.g_a.gy, 32, DEBUG_LOG);

    /* EPID-GID */
    print_debug_binary("msg1.gid", msg1.gid, 4, DEBUG_LOG);


    /* SP側のキーペアを生成 */
    EVP_PKEY *Gb;
    Gb = evp_pkey_generate();

    if(Gb == NULL)
    {
        std::string message = "Failed to generate SP's key pair.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* msg2の生成を開始 */
    print_debug_message("==============================================", INFO);
    print_debug_message("Generate msg2", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);


    /* KDK（鍵導出鍵）の生成 */
    int ret = generate_kdk(Gb, session.kdk, msg1.g_a, config);

    if(ret)
    {
        std::string message = "Failed to derive KDK.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* SMK（Session MAC Key）を導出する。
     * メッセージとしている謎のバイト列はRAのプロトコル仕様によって定められている */
    ret = aes_128bit_cmac(session.kdk,
        (uint8_t*)("\x01SMK\x00\x80\x00"), 7, session.smk);

    if(ret)
    {
        std::string message = "Failed to derive SMK.";
        print_debug_message(message, ERROR);
        return -1;
    }

    print_debug_binary("SMK", session.smk, 16, DEBUG_LOG);

    /* SPのキーペア公開鍵Gbをsgx_ec256_public_tに変換 */
    ret = evp_pubkey_to_sgx_ec256(&msg2.g_b, Gb);

    if(ret)
    {
        std::string message = "Failed to convert Gb to sgx_ec256_public_t.";
        print_debug_message(message, ERROR);
        return -1;
    }

    print_debug_binary("msg2.g_b.gx", msg2.g_b.gx, 32, DEBUG_LOG);
    print_debug_binary("msg2.g_b.gy", msg2.g_b.gy, 32, DEBUG_LOG);

    /* 設定から読み込んだSPID、Quoteタイプをmsg2にコピー */
    memcpy(&msg2.spid, &config.spid, sizeof(sgx_spid_t));
    msg2.quote_type = config.quote_type;

    /* 鍵導出関数IDを設定。通常は1で固定らしい */
    msg2.kdf_id = 1;

    print_debug_binary("msg2.spid",
        (uint8_t*)&msg2.spid, sizeof(sgx_spid_t), DEBUG_LOG);
    
    print_debug_message("msg2.quote_type -> ", DEBUG_LOG);
    print_debug_message(std::to_string(msg2.quote_type), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("msg2.kdf_id -> ", DEBUG_LOG);
    print_debug_message(std::to_string(msg2.kdf_id), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    /* SigRLの取得 */
    uint8_t *sigrl;

    if(get_sigrl(ias, msg1.gid, sigrl, msg2.sig_rl_size))
    {
        std::string message = "Failed to fetch SigRL from IAS.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* SigRLをmsg2にコピー */
    memcpy(msg2.sig_rl, sigrl, msg2.sig_rl_size);

    print_debug_binary("msg2.sig_rl",
        msg2.sig_rl, msg2.sig_rl_size, DEBUG_LOG);

    print_debug_message("msg2.sig_rl_size -> ", DEBUG_LOG);
    print_debug_message(std::to_string(msg2.sig_rl_size), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    /* SigSP生成のため、GbとGaを結合したバイト列を生成 */
    uint8_t gb_ga[128];

    /* 構造体パディングが存在する可能性を鑑みて、メンバごとにコピーする */
    memcpy(gb_ga, msg2.g_b.gx, 32);
    memcpy(&gb_ga[32], msg2.g_b.gy, 32);
    memcpy(&gb_ga[64], msg1.g_a.gx, 32);
    memcpy(&gb_ga[96], msg1.g_a.gy, 32);
	
    /* セッション管理用構造体にもコピー */
    memcpy(session.g_b, msg2.g_b.gx, 32);
    memcpy(&session.g_b[32], msg2.g_b.gy, 32);
    memcpy(session.g_a, msg1.g_a.gx, 32);
    memcpy(&session.g_a[32], msg1.g_a.gy, 32);

    print_debug_binary("Gb_Ga", gb_ga, 128, DEBUG_LOG);


    /* SigSP（Gb_Gaのハッシュに対するECDSA署名）の生成 */
    uint8_t digest[32], r[32], s[32];

    ret = ecdsa_sign(gb_ga, 128,
        config.service_private_key, r, s, digest);

    if(ret)
    {
        print_debug_message("Failed to sign to Gb_Ga.", ERROR);
        return -1;
    }

    print_debug_binary("signature r", r, 32, DEBUG_LOG);
    print_debug_binary("signature s", s, 32, DEBUG_LOG);
    
    /* ECDSA署名r, sをリトルエンディアン化 */
    std::reverse(r, r + 32);
    std::reverse(s, s + 32);

    /* sgx_ec256_signature_tがuint32_t[8]で署名を格納する仕様なので、
     * 強引だがuint8_tポインタで参照し1バイトごとに流し込む */
    uint8_t *msg2_sign_r_u8 = (uint8_t*)msg2.sign_gb_ga.x;
    uint8_t *msg2_sign_s_u8 = (uint8_t*)msg2.sign_gb_ga.y;

    for(int i = 0; i < 32; i++)
    {
        msg2_sign_r_u8[i] = r[i];
        msg2_sign_s_u8[i] = s[i];
    }

    print_debug_binary("reversed signature r",
        (uint8_t*)msg2.sign_gb_ga.x, 32, DEBUG_LOG);
    print_debug_binary("reversed signature s",
        (uint8_t*)msg2.sign_gb_ga.y, 32, DEBUG_LOG);

    /* msg2のコンテンツに対するハッシュ値を計算。
     * 148バイトはGb、SPID、Quoteタイプ、KDF-ID、SigSPの合計サイズ。
     * 構造体パディングを鑑みてメンバごとにコピーする */ 
    uint8_t A[148];

    memcpy(A, msg2.g_b.gx, 32);
    memcpy(&A[32], msg2.g_b.gy, 32);
    memcpy(&A[64], msg2.spid.id, 16);
    memcpy(&A[80], &msg2.quote_type, 2);
    memcpy(&A[82], &msg2.kdf_id, 2);
    memcpy(&A[84], msg2.sign_gb_ga.x, 32);
    memcpy(&A[116], msg2.sign_gb_ga.y, 32);

    print_debug_binary("msg2's A", A, 148, DEBUG_LOG);

    aes_128bit_cmac(session.smk, A, 148, (uint8_t*)msg2.mac);
    
    print_debug_binary(
        "CMAC of A with SMK", msg2.mac, 16, DEBUG_LOG);

    return 0;
}


/* ISVにmsg2を送信し、msg3を受信 */
int send_msg2(std::string ra_ctx_b64, sgx_ra_msg2_t &msg2,
    sgx_ra_msg3_t **msg3, size_t &quote_size, std::string isv_url)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Send msg2", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);
    
    Client client(isv_url);
    json::JSON req_json_obj, res_json_obj;
    std::string request_json;

    /* msg2の各メンバをbase64エンコード */
    std::string Gbx_b64, Gby_b64, spid_b64;
    std::string quote_type_b64, kdf_id_b64;
    std::string sigsp_x_b64, sigsp_y_b64;
    std::string cmac_a_b64, sigrl_b64, sigrl_sz_b64;

    Gbx_b64 = std::string(
        base64_encode<char, uint8_t>(msg2.g_b.gx, 32));
    Gby_b64 = std::string(
        base64_encode<char, uint8_t>(msg2.g_b.gy, 32));
    spid_b64 = std::string(
        base64_encode<char, uint8_t>(msg2.spid.id, 16));

    quote_type_b64 = std::string(
        base64_encode<char, char>((char*)std::to_string(msg2.quote_type).c_str(),
            std::to_string(msg2.quote_type).length()));

    kdf_id_b64 = std::string(
        base64_encode<char, char>((char*)std::to_string(msg2.kdf_id).c_str(),
            std::to_string(msg2.kdf_id).length()));

    sigsp_x_b64 = std::string(
        base64_encode<char, uint8_t>((uint8_t*)msg2.sign_gb_ga.x, 32));
    sigsp_y_b64 = std::string(
        base64_encode<char, uint8_t>((uint8_t*)msg2.sign_gb_ga.y, 32));

    cmac_a_b64 = std::string(
        base64_encode<char, uint8_t>(msg2.mac, 16));

    sigrl_b64 = std::string(
        base64_encode<char, uint8_t>(msg2.sig_rl, msg2.sig_rl_size));

    sigrl_sz_b64 = std::string(
        base64_encode<char, char>((char*)std::to_string(msg2.sig_rl_size).c_str(),
            std::to_string(msg2.sig_rl_size).length()));

    print_debug_message("Base64-encoded msg2 members-------------------", DEBUG_LOG);
    print_debug_message("Gb_x -> " + Gbx_b64, DEBUG_LOG);
    print_debug_message("Gb_y -> " + Gby_b64, DEBUG_LOG);
    print_debug_message("SPID -> " + spid_b64, DEBUG_LOG);
    print_debug_message("Quote Type -> " + quote_type_b64, DEBUG_LOG);
    print_debug_message("KDF-ID -> " + kdf_id_b64, DEBUG_LOG);
    print_debug_message("SigSP_x -> " + sigsp_x_b64, DEBUG_LOG);
    print_debug_message("SigSP_y -> " + sigsp_y_b64, DEBUG_LOG);
    print_debug_message("CMAC(A) with SMK -> " + cmac_a_b64, DEBUG_LOG);
    print_debug_message("SigRL -> " + sigrl_b64, DEBUG_LOG);
    print_debug_message("SigRL size -> " + sigrl_sz_b64, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    /* POSTするJSONに各情報をロード */
    req_json_obj["ra_context"] = ra_ctx_b64;

    req_json_obj["msg2"]["g_b"]["gx"] = Gbx_b64;
    req_json_obj["msg2"]["g_b"]["gy"] = Gby_b64;
    req_json_obj["msg2"]["spid"]["id"] = spid_b64;
    req_json_obj["msg2"]["quote_type"] = quote_type_b64;
    req_json_obj["msg2"]["kdf_id"] = kdf_id_b64;
    req_json_obj["msg2"]["sign_gb_ga"]["x"] = sigsp_x_b64;
    req_json_obj["msg2"]["sign_gb_ga"]["y"] = sigsp_y_b64;
    req_json_obj["msg2"]["mac"] = cmac_a_b64;
    req_json_obj["msg2"]["sig_rl"] = sigrl_b64;
    req_json_obj["msg2"]["sig_rl_size"] = sigrl_sz_b64;

    request_json = req_json_obj.dump();

    /* SP識別用にRAコンテキストを含めてPost */
    auto res = client.Post("/msg2", request_json, "application/json");
    std::string response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    print_debug_message("==============================================", INFO);
    print_debug_message("Process msg3", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else if(res->status != 200)
    {
        std::string message = "Unexpected error while processing msg1.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    size_t tmpsz;

    uint8_t *quote = base64_decode<uint8_t, char>(
        (char*)res_json_obj["msg3"]["quote"].ToString().c_str(), quote_size);

    *msg3 = (sgx_ra_msg3_t*)malloc(sizeof(sgx_ra_msg3_t) + quote_size);

    if(*msg3 == NULL)
    {
        print_debug_message("Failed to allocate memory for msg3.", ERROR);
        return -1;
    }
    
    sgx_ra_msg3_t *msg3tmp = 
        (sgx_ra_msg3_t*)malloc(sizeof(sgx_ra_msg3_t) + quote_size);

    memcpy(msg3tmp->mac, base64_decode<uint8_t, char>(
        (char*)res_json_obj["msg3"]["mac"].ToString().c_str(), tmpsz), 16);
    
    memcpy(msg3tmp->g_a.gx, base64_decode<uint8_t, char>(
        (char*)res_json_obj["msg3"]["g_a"]["gx"].ToString().c_str(), tmpsz), 32);

    memcpy(msg3tmp->g_a.gy, base64_decode<uint8_t, char>(
        (char*)res_json_obj["msg3"]["g_a"]["gy"].ToString().c_str(), tmpsz), 32);

    memcpy(msg3tmp->ps_sec_prop.sgx_ps_sec_prop_desc, base64_decode<uint8_t, char>(
        (char*)res_json_obj["msg3"]["ps_sec_prop"]["sgx_ps_sec_prop_desc"].
        ToString().c_str(), tmpsz), 256);

    memcpy(msg3tmp->quote, quote, quote_size);

    print_debug_binary("msg3.mac", msg3tmp->mac, 16, DEBUG_LOG);
    print_debug_binary("msg3.g_a.gx", msg3tmp->g_a.gx, 32, DEBUG_LOG);
    print_debug_binary("msg3.g_a.gy", msg3tmp->g_a.gy, 32, DEBUG_LOG);
    print_debug_binary("msg3.ps_sec_prop.sgx_ps_sec_prop_desc",
        msg3tmp->ps_sec_prop.sgx_ps_sec_prop_desc, 256, DEBUG_LOG);
    print_debug_binary("msg3.quote", msg3tmp->quote, quote_size, DEBUG_LOG);
    print_debug_message("quote size -> " +
        std::to_string(quote_size), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    memcpy(*msg3, msg3tmp, sizeof(sgx_ra_msg3_t) + quote_size);

    return 0;
}


int process_msg3(std::string ra_ctx_b64, IAS_Communication *ias, 
    sgx_ra_msg1_t msg1, sgx_ra_msg3_t *msg3, size_t quote_size,
    std::string isv_url, sp_ra_session_struct &session,
    sp_config_t config, bool &attestation_accepted)
{
    /* msg3中のGa（ISV公開鍵）がmsg1中のものと一致するか検証する */
    print_debug_binary("msg1.g_a.gx", msg1.g_a.gx, 32, DEBUG_LOG);
    print_debug_binary("msg1.g_a.gy", msg1.g_a.gy, 32, DEBUG_LOG);
    print_debug_binary("msg3.g_a.gx", msg3->g_a.gx, 32, DEBUG_LOG);
    print_debug_binary("msg3.g_a.gy", msg3->g_a.gy, 32, DEBUG_LOG);

    if(CRYPTO_memcmp(&msg3->g_a,
        &msg1.g_a, sizeof(sgx_ec256_public_t)))
    {
        print_debug_message("msg1.g_a and msg3.g_a don't match.", DEBUG_LOG);
        return -1;
    }

    /* msg3に含まれるMAC値（MAC値以外のmsg3のコンテンツに対するSMKによるMAC）
     * を検証する。KDKやそれに依存するSMKは共有秘密由来であるため、
     * 同じ共有秘密を持つEnclaveもこれらの値は把握している */
    sgx_mac_t verification_mac; //これがmsg3中のmacと一致していればOK
    aes_128bit_cmac(session.smk, (uint8_t*)&msg3->g_a,
        sizeof(sgx_ra_msg3_t) + quote_size - sizeof(sgx_mac_t),
        verification_mac);

    print_debug_binary("msg3.mac", msg3->mac, 16, DEBUG_LOG);
    print_debug_binary("verification mac", verification_mac, 16, DEBUG_LOG);

    if(CRYPTO_memcmp(msg3->mac, verification_mac, 16))
    {
        print_debug_message("Failed to verify msg3 MAC.", ERROR);
        return -1;
    }

    /* IAS送信向けにQuote構造体をBase64エンコード*/
    char *quote_b64 = base64_encode<char, uint8_t>(
        (uint8_t*)&msg3->quote, quote_size);
    
    if(quote_b64 == NULL)
    {
        print_debug_message("Failed to encode Quote to Base64.", ERROR);
        return -1;
    }

    /* msg3中のEPID-GIDがmsg1中のものと一致するか検証する */
    sgx_quote_t *quote = (sgx_quote_t*)msg3->quote;
    print_debug_binary("msg1.gid",
        msg1.gid, sizeof(sgx_epid_group_id_t), DEBUG_LOG);
    print_debug_binary("msg3.quote.epid_group_id",
        (uint8_t*)&quote->epid_group_id, sizeof(sgx_epid_group_id_t),
        DEBUG_LOG);

    if(memcmp(msg1.gid, &quote->epid_group_id, sizeof(sgx_epid_group_id_t)))
    {
        print_debug_message(
            "EPID-GID mismatch between msg1 and msg3.", ERROR);
        free(quote_b64);

        return -1;
    }

    /* Quote内のReport構造体内にさらに存在する
     * sgx_report_data_tの先頭32バイトを検証する */
    uint8_t ga_gb_vk[144]; // Ga || Gb || VK
    sgx_report_body_t *report = (sgx_report_body_t*)&quote->report_body;

    //VKの導出
    aes_128bit_cmac(session.kdk, 
        (uint8_t*)("\x01VK\x00\x80\x00"), 6, session.vk);
    
    memcpy(ga_gb_vk, session.g_a, 64);
    memcpy(&ga_gb_vk[64], session.g_b, 64);
    memcpy(&ga_gb_vk[128], session.vk, 16);

    uint8_t verifiy_report_data[32];
    memset(verifiy_report_data, 0, 32);

    //Ga || Gb || VKのSHA256ハッシュを取得
    sha256_digest(ga_gb_vk, 144, verifiy_report_data);

    print_debug_binary("VK", session.vk, 16, DEBUG_LOG);
    print_debug_binary("SHA256(Ga||Gb||VK)", ga_gb_vk, 32, DEBUG_LOG);
    print_debug_binary("report data inside report body in received quote",
        (uint8_t*)&report->report_data, 64, DEBUG_LOG);
    
    /* report_dataの先頭32バイトの検証。report_dataは合計64バイト存在し、
     * 後半32バイトはISVとSPで示し合わせて任意の用途で利用できる。
     * 利用する際は目的に応じて追加の処理を実装する必要がある */
    if(CRYPTO_memcmp((void*)verifiy_report_data,
        (void*)&report->report_data, 32))
    {
        std::string message = "Invalid report data (Ga||Gb||VK).";
        print_debug_message(message, ERROR);
        return -1;
    }


    /* Quote構造体の中身をデバッグ表示 */
    print_debug_binary("msg3.quote.version",
        (uint8_t*)&quote->version, sizeof(uint16_t), DEBUG_LOG);
    print_debug_binary("msg3.quote.sign_type",
        (uint8_t*)&quote->sign_type, sizeof(uint16_t), DEBUG_LOG);
    print_debug_binary("msg3.quote.epid_group_id",
        (uint8_t*)&quote->epid_group_id, sizeof(sgx_epid_group_id_t),
        DEBUG_LOG);
    print_debug_binary("msg3.quote.qe_svn",
        (uint8_t*)&quote->qe_svn, sizeof(sgx_isv_svn_t), DEBUG_LOG);
    print_debug_binary("msg3.quote.pce_svn",
        (uint8_t*)&quote->pce_svn, sizeof(sgx_isv_svn_t), DEBUG_LOG);
    print_debug_binary("msg3.quote.xeid",
        (uint8_t*)&quote->xeid, sizeof(uint32_t), DEBUG_LOG);
    print_debug_binary("msg3.quote.basename",
        (uint8_t*)&quote->basename, sizeof(sgx_basename_t), DEBUG_LOG);
    print_debug_binary("msg3.quote.report_body",
        (uint8_t*)&quote->report_body, sizeof(sgx_report_body_t),
        DEBUG_LOG);
    print_debug_binary("msg3.quote.signature_len",
        (uint8_t*)&quote->signature_len, sizeof(uint32_t), DEBUG_LOG);
    print_debug_binary("msg3.quote.signature",
        (uint8_t*)&quote->signature, quote->signature_len, DEBUG_LOG);

    print_debug_message("Quote in Base64 -> ", DEBUG_LOG);
    print_debug_message(quote_b64, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);


    /* IASにQuoteを送信 */
    ra_msg4_t msg4;

    if(get_attestation_report(ias, quote_b64, &msg4)) return -1;

    /* MRENCLAVE, MRSIGNER, ISVSVN, ISVProdIDと比較 */
    verify_enclave(&msg4, report, config);

    /* RAを受理するかを判定する */
    if(msg4.status != NotTrusted) attestation_accepted = true;
    else attestation_accepted = false;

    Client client(isv_url);
    json::JSON req_json_obj, res_json_obj;
    std::string request_json;

    std::string ra_status_str;

    if(msg4.status == Trusted) ra_status_str = "Trusted";
    else if(msg4.status == Conditionally_Trusted)
        ra_status_str = "Conditionally_Trusted";
    else ra_status_str = "NotTrusted";

    req_json_obj["ra_context"] = ra_ctx_b64;

    req_json_obj["msg4"]["status"] = std::string(base64_encode<char, char>(
        (char*)ra_status_str.c_str(), ra_status_str.length()));

    req_json_obj["msg4"]["description"] = std::string(
        base64_encode<char, char>(msg4.description, 512));

    req_json_obj["msg4"]["pib"] = std::string(base64_encode<char, uint8_t>(
        msg4.pib.platform_info, SGX_PLATFORM_INFO_SIZE));

    request_json = req_json_obj.dump();

    /* msg4をISVに送信 */
    auto res = client.Post("/msg4", request_json, "application/json");

    if(res->status != 200)
    {
        print_debug_message("Failed to send msg4.", ERROR);
        return -1;
    }

    return 0;
}


/* Remote Attestationを実行する関数。 */
int do_RA(std::string isv_url, std::string &ra_ctx_b64, 
    uint8_t *&sk, uint8_t *&mk)
{
    sp_config_t config;

    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Remote Attestation Preparation", INFO);
    print_debug_message("==============================================", INFO);

    /* 暗号処理関数向けの初期化（事前処理） */
    crypto_init();


    /* settings.iniで記述している各種設定を読み込む。
     * settings.iniから読み込まないような設定についてもここで実行する */
    int ret = -1;
    ret = load_settings(config);
    if(ret)
    {
        std::string message = "Failed to load settings.";
        print_debug_message(message, ERROR);
        return -1;
    }


    /* IAS接続機構オブジェクトを初期化 */
    IAS_Communication *ias = NULL;

    try
    {
        ias = new IAS_Communication(
            IAS_SERVER_DEVELOPMENT, 
            (char*)config.primary_key,
            (char*)config.secondary_key
        );
    }
    catch(...)
    {
        std::string message = "Failed to create IAS connection object.";
        print_debug_message(message, ERROR);
        return -1;
    }

    ias->set_cert_store(config.store);

    /* チャレンジリクエストを送信しmsg0を受信 */
    uint32_t extended_epid_group_id = 0;
    int status = 0;
    
    status = process_msg0(ra_ctx_b64, extended_epid_group_id, isv_url);
    if(status) return -1;


    /* RAコンテキストを送信しmsg1を受信及び処理しmsg2を生成 */
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t msg2;
    sgx_ra_msg3_t *msg3; //ポインタでないと上手くQuoteを持って来れない
    sp_ra_session_t session;

    memset(&session, 0, sizeof(sp_ra_session_t));


    /* msg1を受信しmsg2を作成 */
    status = process_msg1(ra_ctx_b64, ias, 
        msg1, msg2, config, session, isv_url);

    if(status) return -1;
    

    /* msg2を送信しmsg3を受信 */
    size_t quote_size = 0;
    status = send_msg2(ra_ctx_b64, 
        msg2, &msg3, quote_size, isv_url);

    if(status) return -1;

    /* msg3を処理しアテステーション結果を決定後msg4を送信 */
    bool attestation_accepted = false;
    status = process_msg3(ra_ctx_b64, ias, msg1, msg3,
        quote_size, isv_url, session, config, attestation_accepted);

    if(!attestation_accepted)
    {
        print_debug_message("----------------------------------------------", ERROR);
        print_debug_message("Refused RA.", ERROR);
        print_debug_message("----------------------------------------------", ERROR);
        print_debug_message("", ERROR);
        free(msg3);

        return -1;
    }

    print_debug_message("----------------------------------------------", INFO);
    print_debug_message("Accepted RA. Proceed to next process.", INFO);
    print_debug_message("----------------------------------------------", INFO);
    print_debug_message("", INFO);

    /* セッション鍵であるSKとMKを生成 */
    aes_128bit_cmac(session.kdk, (uint8_t*)("\x01SK\x00\x80\x00"),
        6, session.sk);
    aes_128bit_cmac(session.kdk, (uint8_t*)("\x01MK\x00\x80\x00"),
        6, session.mk);

    print_debug_binary("SK", session.sk, 16, DEBUG_LOG);
    print_debug_binary("MK", session.mk, 16, DEBUG_LOG);

    print_debug_message("Generated SK and MK (session keys).", INFO);
    print_debug_message("", INFO);

    sk = new uint8_t[16]();
    mk = new uint8_t[16]();

    memcpy(sk, session.sk, 16);
    memcpy(mk, session.mk, 16);


    free(msg3);

    return 0;
}


/* CSPRNGにより、指定されたバイト数だけ乱数（nonce）を生成 */
int generate_nonce(uint8_t *buf, size_t size)
{
    int ret = RAND_bytes(buf, size);

    if(!ret)
    {
        print_debug_message("Failed to generate nonce.", ERROR);
        return -1;
    }
    else return 0;
}


/* 128bit AES/GCMで暗号化する。SKやMKを用いた、ISVの
 * Enclaveとの暗号化通信を行うために利用可能 */
int aes_128_gcm_encrypt(uint8_t *plaintext, size_t p_len,
    uint8_t *key, uint8_t *iv, uint8_t *ciphertext, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx;
    size_t c_len;
    int len_tmp;
    std::string message;

    /* コンテキストの作成 */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        message = "Failed to initialize context for GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM暗号化初期化処理 */
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
    {
        message = "Failed to initialize GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 暗号化する平文を供給する */
    if(!EVP_EncryptUpdate(ctx, ciphertext, &len_tmp, plaintext, p_len))
    {
        message = "Failed to encrypt plain text with GCM.";
        print_debug_message(message, ERROR);
        return -1;
    }

    c_len = len_tmp;

    /* GCM暗号化の最終処理 */
    if(!EVP_EncryptFinal_ex(ctx, ciphertext + len_tmp, &len_tmp))
    {
        message = "Failed to finalize GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    c_len += len_tmp;

    /* 生成したGCM暗号文のMACタグを取得 */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    {
        message = "Failed to obtain GCM MAC tag.";
        print_debug_message(message, ERROR);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return c_len;
}


/* 128bit AES/GCMで復号する。SKやMKを用いた、ISVの
 * Enclaveとの暗号化通信を行うために利用可能 */
int aes_128_gcm_decrypt(uint8_t *ciphertext, size_t c_len,
    uint8_t *key, uint8_t *iv, uint8_t *tag, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    size_t p_len;
    int ret, len_tmp;
    std::string message;

    /* コンテキストの作成 */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        message = "Failed to initialize context for GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM復号初期化処理 */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
    {
        message = "Failed to initialize GCM decryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 復号する暗号文を供給する */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len_tmp, ciphertext, c_len))
    {
        message = "Failed to decrypt cipher text with GCM.";
        print_debug_message(message, ERROR);
        return -1;
    }

    p_len = len_tmp;

    /* 検証に用いるGCM MACタグをセット */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    {
        message = "Failed to set expected GCM MAC tag.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM復号の最終処理 */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len_tmp, &len_tmp);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        p_len += len_tmp;
        return p_len;
    }
    else
    {
        /* 復号または検証の失敗 */
        message = "Decryption verification failed.";
        print_debug_message(message, ERROR);
        return -1;
    }
}


/* TLS通信を通したリモート秘密計算のテスト */
int sample_remote_computation(std::string isv_url,
    std::string &ra_ctx_b64, uint8_t *&sk, uint8_t *&mk)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Sample Remote Computation", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    uint64_t secret_1 = 200;
    uint64_t secret_2 = 800;
    std::string secret_1_str = std::to_string(secret_1);
    std::string secret_2_str = std::to_string(secret_2);

    print_debug_message("First integer to send -> ", INFO);
    print_debug_message(secret_1_str, INFO);
    print_debug_message("", INFO);
    print_debug_message("Second integer to send -> ", INFO);
    print_debug_message(secret_2_str, INFO);
    print_debug_message("", INFO);

    uint8_t *plain_send_1 = (uint8_t*)secret_1_str.c_str();
    uint8_t *plain_send_2 = (uint8_t*)secret_2_str.c_str();

    size_t secret_1_len = secret_1_str.length();
    size_t secret_2_len = secret_2_str.length();

    uint8_t *iv_send = new uint8_t[12]();
    uint8_t *tag_send_1 = new uint8_t[16]();
    uint8_t *tag_send_2 = new uint8_t[16]();

    /* GCM方式は平文と暗号文の長さが同一 */
    uint8_t *cipher_send_1 = new uint8_t[secret_1_len]();
    uint8_t *cipher_send_2 = new uint8_t[secret_2_len]();

    if(generate_nonce(iv_send, 12)) return -1;

    /* SKで暗号化 */
    if(-1 == (aes_128_gcm_encrypt(plain_send_1,
        secret_1_len, sk, iv_send, cipher_send_1, tag_send_1)))
    {
        return -1;
    }

    if(-1 == (aes_128_gcm_encrypt(plain_send_2,
        secret_2_len, sk, iv_send, cipher_send_2, tag_send_2)))
    {
        return -1;
    }

    char *cs1_b64, *cs2_b64;
    char *ivs_b64;
    char *tags1_b64, *tags2_b64;

    cs1_b64 = base64_encode<char, uint8_t>(cipher_send_1, secret_1_len);
    cs2_b64 = base64_encode<char, uint8_t>(cipher_send_2, secret_2_len);
    ivs_b64 = base64_encode<char, uint8_t>(iv_send, 12);
    tags1_b64 = base64_encode<char, uint8_t>(tag_send_1, 16);
    tags2_b64 = base64_encode<char, uint8_t>(tag_send_2, 16);

    json::JSON req_json_obj, res_json_obj;
    std::string request_json, response_json;

    req_json_obj["ra_context"] = ra_ctx_b64;
    req_json_obj["cipher1"] = cs1_b64;
    req_json_obj["cipher2"] = cs2_b64;
    req_json_obj["iv"] = ivs_b64;
    req_json_obj["tag1"] = tags1_b64;
    req_json_obj["tag2"] = tags2_b64;

    Client client(isv_url);

    request_json = req_json_obj.dump();

    /* 計算に使用する暗号データを送信 */
    auto res = client.Post("/sample-addition", request_json, "application/json");
    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else if(res->status != 200)
    {
        std::string message = "Unexpected error while processing msg0.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    /* 受信した計算結果暗号文の処理を開始 */
    uint8_t *cipher_result, *plain_result;
    uint8_t *iv_result, *tag_result;
    size_t cipher_result_len, tmpsz;

    cipher_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["cipher"].ToString().c_str(), cipher_result_len);
    
    /* GCMでは暗号文と平文の長さが同一 */
    plain_result = new uint8_t[cipher_result_len]();

    iv_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["iv"].ToString().c_str(), tmpsz);

    if(tmpsz != 12)
    {
        print_debug_message("Invalidly formatted IV received.", ERROR);
        return -1;
    }

    tag_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["tag"].ToString().c_str(), tmpsz);
    
    if(tmpsz != 16)
    {
        print_debug_message("Invalidly formatted MAC tag received.", ERROR);
        return -1;
    }

    if(-1 == (aes_128_gcm_decrypt(cipher_result,
        cipher_result_len, mk, iv_result, tag_result, plain_result)))
    {
        return -1;
    }

    uint64_t total = atol((const char*)plain_result);

    /* 受信した計算結果の表示 */
    print_debug_message("Received addition result -> ", INFO);
    print_debug_message(std::to_string(total), INFO);

    return 0;
}


/* 処理終了後はRAコンテキストをISVに破棄させる */
void destruct_ra_context(std::string isv_url, std::string ra_ctx_b64)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Destruct RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);
    
    json::JSON req_json_obj;
    std::string request_json;

    req_json_obj["ra_context"] = ra_ctx_b64;

    Client client(isv_url);

    request_json = req_json_obj.dump();

    /* 計算に使用する暗号データを送信 */
    auto res = client.Post("/destruct-ra", request_json, "application/json");

    print_debug_message("Sent RA destruction request to ISV.", INFO);
    print_debug_message("", INFO);
}


void main_process()
{
    /* ISVのURLを設定 */
    std::string isv_url = "http://localhost:1234";

    /* ISVはこの変数を用いてSP（厳密にはRA）の識別を行う。
     * SPは直接は使わないので、通信向けにbase64の形で保持 */
    std::string ra_ctx_b64 = "";
    
    /* RA後のTLS通信用のセッション鍵（共有秘密）。SKとMKの2つが導出されるが、
     * 慣習的にSKの方が使用される事が多い。
     * do_RA関数内で取得され引数経由で返される。 */
    uint8_t *sk;
    uint8_t *mk;

    int ret = -1;

    /* RAを実行 */
    ret = do_RA(isv_url, ra_ctx_b64, sk, mk);

    if(ret)
    {
        std::string message = "RA failed. Destruct RA context and Exit program.";
        print_debug_message(message, ERROR);
        destruct_ra_context(isv_url, ra_ctx_b64);
        exit(0);
    }

    print_debug_binary("SK", sk, 16, DEBUG_LOG);
    print_debug_binary("MK", mk, 16, DEBUG_LOG);

    /* TLS通信を通したリモート秘密計算のテスト */
    ret = sample_remote_computation(isv_url, ra_ctx_b64, sk, mk);

    /* RAコンテキストの破棄 */
    destruct_ra_context(isv_url, ra_ctx_b64);

    free(sk);
    free(mk);
}


int main()
{
    std::string message = "Launched SP's untrusted application.";
    print_debug_message(message, INFO);

    main_process();

    return 0;
}