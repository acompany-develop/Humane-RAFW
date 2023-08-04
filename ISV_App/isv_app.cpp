#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <sgx_urts.h>
#include <sgx_uswitchless.h>
#include <sgx_ukey_exchange.h>
#include <sgx_uae_epid.h>
#include "error_print.hpp"
#include "isv_enclave_u.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../include/httplib.h"
#include "../include/json.hpp"
#include "../common/base64.hpp"
#include "../common/debug_print.hpp"
#include "../common/hexutil.hpp"
#include "../common/attestation_status.hpp"


using namespace httplib;


/* プロトタイプ宣言 */
int initialize_enclave(sgx_enclave_id_t &eid);

int generate_msg0(sgx_enclave_id_t eid,
    std::string &response_json, std::string &error_message);

int get_msg1(sgx_enclave_id_t eid, std::string request_json,
    std::string &response_json, std::string &error_message);

int process_msg2(sgx_enclave_id_t eid, std::string request_json,
    std::string &response_json, std::string &error_message);

int process_msg4(sgx_enclave_id_t eid,
    std::string request_json, std::string &error_message);

int sample_addition(sgx_enclave_id_t eid, std::string request_json,
    std::string &response_json, std::string error_message);

void destruct_ra_context(sgx_enclave_id_t eid, std::string request_json);


/* Enclave内の値の出力を行うOCALL（主にデバッグやログ用） */
void ocall_print(const char *str, int log_type)
{
    MESSAGE_TYPE type;
    if(log_type == 0) type = DEBUG_LOG;
    else if(log_type == 1) type = INFO;
    else type = ERROR;
 
    print_debug_message("OCALL output-> ", type);
    print_debug_message(str, type);

    return;
}


/* SGXステータスを識別し具体的な内容表示する */
void ocall_print_status(sgx_status_t st)
{
	print_sgx_status(st);
	return;
}


/* サーバの実行定義。RA含む各処理はここで完結する */
void server_logics(sgx_enclave_id_t eid)
{
    Server svr;

    /* チャレンジリクエストに応じmsg0を返信 */
    svr.Get("/msg0", [&eid](const Request& req, Response& res)
    {
        std::string response_json, error_message = "";
        int ret = generate_msg0(eid, response_json, error_message);

        if(!ret) res.status = 200; //正常時
        else //異常時
        {
            /* 通信用にBase64化 */
            char *error_message_b64;
            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());
            
            /* レスポンス用jsonを生成 */
            json::JSON json_obj;
            json_obj["error_message"] = std::string(error_message_b64);
            response_json = json_obj.dump();

            res.status = 500;
        }

        /* レスポンスを返信 */
        res.set_content(response_json, "application/json");
    });


    /* RAコンテキストでSPを識別しmsg1を返信 */
    svr.Post("/msg1", [&eid](const Request& req, Response& res)
    {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        /* msg1を取得する */
        int ret = get_msg1(eid, request_json, response_json, error_message);

        if(!ret) res.status = 200;
        else
        {
            /* 通信用にBase64化 */
            char *error_message_b64;
            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());
            
            /* レスポンス用jsonを生成 */
            json::JSON json_obj;
            json_obj["error_message"] = std::string(error_message_b64);
            response_json = json_obj.dump();

            res.status = 500;
        }

        /* レスポンスを返信 */
        res.set_content(response_json, "application/json");
    });


    /* msg2を受信・処理しmsg3を返信 */
    svr.Post("/msg2", [&eid](const Request& req, Response& res)
    {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        int ret = process_msg2(eid, request_json,
            response_json, error_message);

        if(!ret) res.status = 200;
        else
        {
            /* 通信用にBase64化 */
            char *error_message_b64;
            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());
            
            /* レスポンス用jsonを生成 */
            json::JSON json_obj;
            json_obj["error_message"] = std::string(error_message_b64);
            response_json = json_obj.dump();

            res.status = 500;
        }

        res.set_content(response_json, "application/json");
    });


    /* msg4を受信し処理 */
    svr.Post("/msg4", [&eid](const Request& req, Response& res)
    {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        int ret = process_msg4(eid, request_json, error_message);
        json::JSON res_json_obj;

        if(!ret)
        {
            res.status = 200;
            res_json_obj["message"] = std::string("OK");
        }
        else
        {
            res.status = 500;
            res_json_obj["error_message"] = error_message;
        }

        response_json = res_json_obj.dump();

        res.set_content(response_json, "application/json");
    });


    /* リモート計算処理テスト（受信した秘密情報のEnclave内での加算） */
    svr.Post("/sample-addition", [&eid](const Request& req, Response& res)
    {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        int ret = sample_addition(eid, request_json,
            response_json, error_message);

        if(!ret) res.status = 200;
        else
        {
            json::JSON res_json_obj;
            char *error_message_b64;

            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());
            
            res_json_obj["error_message"] = std::string(error_message_b64);
            response_json = res_json_obj.dump();

            res.status = 500;
        }

        print_debug_message("send the result response to SP.", INFO);
        print_debug_message("", INFO);

        res.set_content(response_json, "application/json");
    });


    /* 受信したRAコンテキストのRAを終了する */
    svr.Post("/destruct-ra", [&eid](const Request& req, Response& res)
    {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        destruct_ra_context(eid, request_json);

        res.status = 200;
        json::JSON res_json_obj;
        res_json_obj["message"] = std::string("OK");
        response_json = res_json_obj.dump();

        res.set_content(response_json, "application/json");
    });


    svr.Get("/hi", [](const Request& req, Response& res) {
    res.set_content("Hello World!", "text/plain");
    });

    svr.Get("/stop", [&](const Request& req, Response& res) {
        /* Enclaveの終了 */
        sgx_destroy_enclave(eid);

        svr.stop();
    });

    svr.listen("localhost", 1234);
}


/* msg0（に使用する各データ）を生成 */
int generate_msg0(sgx_enclave_id_t eid,
    std::string &response_json, std::string &error_message)
{
    sgx_ra_context_t ra_ctx = -1;
    uint32_t extended_epid_group_id = -1;
    sgx_status_t status, retval;

    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Process msg0", INFO);
    print_debug_message("==============================================", INFO);

    /* RAを初期化し、RA識別用のコンテキスト値を取得する */
    status = ecall_ra_init(eid, &retval, &ra_ctx);

    if(status != SGX_SUCCESS || retval != SGX_SUCCESS)
    {
        std::string message;

        if(status != SGX_SUCCESS)
        {
            message = "Failed to ECALL for RA initialization.";
        }
        else
        {
            message = "Failed to initialize Remote Attestation.";
        }

        error_message = message;

        print_sgx_status(status);
        
        return -1;
    }


    /* 拡張EPID-GIDを取得 */
    status = sgx_get_extended_epid_group_id(&extended_epid_group_id);

    if(status != SGX_SUCCESS)
    {
        sgx_status_t retval;
        ecall_ra_close(eid, &retval, ra_ctx);
        error_message = "Failed to get extended EPID-GID.";
        print_sgx_status(status);

        return -1;
    }

    print_debug_message("RA context number -> " +
        std::to_string(ra_ctx), DEBUG_LOG);
    print_debug_message("Extended EPID group ID -> " + 
        std::to_string(extended_epid_group_id), DEBUG_LOG);
    print_debug_message("Generating msg0 completed.", INFO);


    /* レスポンス用JSONを生成 */
    std::string ra_ctx_str, ex_epid_gid_str;
    char *ra_ctx_b64, *ex_epid_gid_b64;

    ra_ctx_str = std::to_string(ra_ctx);
    ex_epid_gid_str = std::to_string(extended_epid_group_id);

    /* 通信用にBase64化 */
    ra_ctx_b64 = base64_encode<char, char>(
        (char*)ra_ctx_str.c_str(), ra_ctx_str.length());
    
    ex_epid_gid_b64 = base64_encode<char, char>(
        (char*)ex_epid_gid_str.c_str(), ex_epid_gid_str.length());

    /* レスポンス用jsonを生成 */
    json::JSON res_json_obj;
    res_json_obj["ra_context"] = std::string(ra_ctx_b64);
    res_json_obj["extended_epid_gid"] = std::string(ex_epid_gid_b64);
    response_json = res_json_obj.dump();

    return 0;
}


/* msg1を取得 */
int get_msg1(sgx_enclave_id_t eid, std::string request_json,
    std::string &response_json, std::string &error_message)
{
    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Process msg1", INFO);
    print_debug_message("==============================================", INFO);

    size_t ra_ctx_char_size;
    sgx_status_t status;

    json::JSON req_json_obj = json::JSON::Load(request_json);

    std::string ra_ctx_str = std::string(base64_decode<char, char>(
        (char*)req_json_obj["ra_context"].ToString().c_str(), ra_ctx_char_size));

    sgx_ra_context_t ra_ctx;
    
    try
    {
        ra_ctx = std::stoi(ra_ctx_str);
    }
    catch(...)
    {
        print_debug_message("Invalid RA context format.", ERROR);
        return -1;
    }

    sgx_ra_msg1_t msg1;

    /* msg1を取得する。sgx_ra_get_gaは、ISV側のキーペアであるGaを
     * 生成するためのプロキシ関数（sgx_tkey_exchange.edlにより
     * 提供される）への関数ポインタである */
    status = sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);

    if(status != SGX_SUCCESS)
    {
        sgx_status_t retval;
        ecall_ra_close(eid, &retval, ra_ctx);
        error_message = "Failed to obtain msg1.";
        return -1;
    }

    /* msg1の内容をデバッグ表示。まずはキーペア公開鍵x成分 */
    print_debug_binary("msg1.g_a.gx", msg1.g_a.gx, 32, DEBUG_LOG);

    /* キーペア公開鍵y成分 */
    print_debug_binary("msg1.g_a.gy", msg1.g_a.gy, 32, DEBUG_LOG);

    /* EPID-GID */
    print_debug_binary("msg1.gid", msg1.gid, 4, DEBUG_LOG);


    /* レスポンス用JSONを生成 */
    std::string pub_gx_b64, pub_gy_b64; //キーペアの内公開鍵のx, y成分をBase64形式で保持
    std::string gid_b64; //EPID-GIDをBase64形式で保持
    json::JSON res_json_obj;

    pub_gx_b64 = std::string(
        base64_encode<char, uint8_t>(msg1.g_a.gx, 32));
    pub_gy_b64 = std::string(
        base64_encode<char, uint8_t>(msg1.g_a.gy, 32));
    gid_b64 = std::string(
        base64_encode<char, uint8_t>(msg1.gid, 4));

    res_json_obj["msg1"]["g_a"]["gx"] = pub_gx_b64;
    res_json_obj["msg1"]["g_a"]["gy"] = pub_gy_b64;
    res_json_obj["msg1"]["gid"] = gid_b64;

    response_json = res_json_obj.dump();

    return 0;
}


/* msg2を処理しmsg3を生成 */
int process_msg2(sgx_enclave_id_t eid, std::string request_json,
    std::string &response_json, std::string &error_message)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Process msg2", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj = json::JSON::Load(request_json);
    size_t tmpsz;

    std::string ra_ctx_str = std::string(base64_decode<char, char>(
        (char*)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

    sgx_ra_context_t ra_ctx;
    
    try
    {
        ra_ctx = std::stoi(ra_ctx_str);
    }
    catch(...)
    {
        print_debug_message("Invalid RA context format.", ERROR);
        return -1;
    }

    /* 受信データをmsg2に変換 */
    sgx_ra_msg2_t msg2;

    /* SPの公開鍵 */
    memcpy(msg2.g_b.gx, base64_decode<uint8_t, char>(
        (char*)req_json_obj["msg2"]["g_b"]["gx"].ToString().c_str(), tmpsz), 32);
    memcpy(msg2.g_b.gy, base64_decode<uint8_t, char>(
        (char*)req_json_obj["msg2"]["g_b"]["gy"].ToString().c_str(), tmpsz), 32);
    
    /* SPID */
    memcpy(msg2.spid.id, base64_decode<uint8_t, char>(
        (char*)req_json_obj["msg2"]["spid"]["id"].ToString().c_str(), tmpsz), 16);

    /* Quoteタイプと鍵導出関数ID */
    msg2.quote_type = std::stoi(std::string(base64_decode<char, char>(
        (char*)req_json_obj["msg2"]["quote_type"].ToString().c_str(), tmpsz)));
    msg2.kdf_id = std::stoi(std::string(base64_decode<char, char>(
        (char*)req_json_obj["msg2"]["kdf_id"].ToString().c_str(), tmpsz)));

    /* Gb_Gaに対するECDSA署名 */
    memcpy(msg2.sign_gb_ga.x, base64_decode<uint8_t, char>(
        (char*)req_json_obj["msg2"]["sign_gb_ga"]["x"].ToString().c_str(), tmpsz), 32);
    memcpy(msg2.sign_gb_ga.y, base64_decode<uint8_t, char>(
        (char*)req_json_obj["msg2"]["sign_gb_ga"]["y"].ToString().c_str(), tmpsz), 32);

    /* 上記データ群（A）に対するCMAC値 */
    memcpy(msg2.mac, base64_decode<uint8_t, char>(
        (char*)req_json_obj["msg2"]["mac"].ToString().c_str(), tmpsz), 16);
    
    /* SigRLのサイズとSigRL */
    msg2.sig_rl_size = std::stoi(std::string(base64_decode<char, char>(
        (char*)req_json_obj["msg2"]["sig_rl_size"].ToString().c_str(), tmpsz)));
    
    memcpy(msg2.sig_rl, base64_decode<uint8_t, char>(
        (char*)req_json_obj["msg2"]["sig_rl"].
            ToString().c_str(), tmpsz), msg2.sig_rl_size);

    print_debug_message(
        "Received msg2 data----------------------------", DEBUG_LOG);

    print_debug_binary("msg2.g_b.gx", msg2.g_b.gx, 32, DEBUG_LOG);
    print_debug_binary("msg2.g_b.gy", msg2.g_b.gy, 32, DEBUG_LOG);
    print_debug_binary("msg2.spid.id", msg2.spid.id, 16, DEBUG_LOG);

    print_debug_message("msg2.quote_type -> ", DEBUG_LOG);
    print_debug_message(std::to_string(msg2.quote_type), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("msg2.kdf_id -> ", DEBUG_LOG);
    print_debug_message(std::to_string(msg2.kdf_id), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_binary("msg2.sign_gb_ga.x",
        (uint8_t*)msg2.sign_gb_ga.x, 32, DEBUG_LOG);
    print_debug_binary("msg2.sign_gb_ga.y",
        (uint8_t*)msg2.sign_gb_ga.y, 32, DEBUG_LOG);
    print_debug_binary("msg2.mac", msg2.mac, 16, DEBUG_LOG);

    print_debug_message("msg2.sig_rl_size -> ", DEBUG_LOG);
    print_debug_message(std::to_string(msg2.sig_rl_size), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    if(msg2.sig_rl_size == 0)
    {
        print_debug_message("msg2.sig_rl -> ", DEBUG_LOG);
        print_debug_message("(none)", DEBUG_LOG);
    }
    else
    {
        print_debug_binary("msg2.sig_rl",
            msg2.sig_rl, msg2.sig_rl_size, DEBUG_LOG);
    }
    
    print_debug_message(
        "----------------------------------------------", DEBUG_LOG);
    

    print_debug_message("==============================================", INFO);
    print_debug_message("Process msg3", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);
    
    sgx_ra_msg3_t *msg3;
    sgx_status_t status;
    uint32_t msg3_size;

    /* msg2を処理しmsg3を取得する。
     * sgx_ra_proc_msg2_trusted及びsgx_ra_get_msg3_trustedは、
     * sgx_tkey_exchange.edlにより提供されているプロキシ関数ポインタである */
    status = sgx_ra_proc_msg2(ra_ctx, eid, 
        sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
        &msg2, sizeof(sgx_ra_msg2_t) + msg2.sig_rl_size, &msg3, &msg3_size);

    if(status != SGX_SUCCESS)
    {
        print_sgx_status(status);
        sgx_status_t retval;
        ecall_ra_close(eid, &retval, ra_ctx);
        error_message = "Failed to process msg2 and obtain msg3.";
        return -1;
    }

    /* msg3の内容のデバッグ表示 */
    size_t quote_size = msg3_size - sizeof(sgx_ra_msg3_t);

    print_debug_binary("msg3.mac", msg3->mac, 16, DEBUG_LOG);
    print_debug_binary("msg3.g_a.gx", msg3->g_a.gx, 32, DEBUG_LOG);
    print_debug_binary("msg3.g_a.gy", msg3->g_a.gy, 32, DEBUG_LOG);
    print_debug_binary("msg3.ps_sec_prop.sgx_ps_sec_prop_desc",
        msg3->ps_sec_prop.sgx_ps_sec_prop_desc, 256, DEBUG_LOG);
    print_debug_binary("msg3.quote",
        msg3->quote, quote_size, DEBUG_LOG);
    
    /* quoteは以下の記述でも正常に出力できる。参考までに掲載
    sgx_quote_t *quote = (sgx_quote_t*)msg3->quote;
    print_debug_message(std::to_string(quote->signature_len), DEBUG_LOG);
    print_debug_binary("msg3.quote",
        msg3->quote, 436 + quote->signature_len, DEBUG_LOG);
    */

    print_debug_message("size of quote -> ", DEBUG_LOG);
    print_debug_message(std::to_string(quote_size), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);


    /* msg3の内容をレスポンスのJSONにロード */
    json::JSON res_json_obj;

    res_json_obj["msg3"]["mac"] = 
        std::string(base64_encode<char, uint8_t>(msg3->mac, 16));

    res_json_obj["msg3"]["g_a"]["gx"] = 
        std::string(base64_encode<char, uint8_t>(msg3->g_a.gx, 32));

    res_json_obj["msg3"]["g_a"]["gy"] = 
        std::string(base64_encode<char, uint8_t>(msg3->g_a.gy, 32));

    res_json_obj["msg3"]["ps_sec_prop"]["sgx_ps_sec_prop_desc"] = 
        std::string(base64_encode<char, uint8_t>(
            msg3->ps_sec_prop.sgx_ps_sec_prop_desc, 256));

    res_json_obj["msg3"]["quote"] = 
        std::string(base64_encode<char, uint8_t>(msg3->quote, quote_size));
    
    print_debug_message("Base64-encoded msg3 members-------------------", DEBUG_LOG);
    
    print_debug_message("msg3.mac -> " + 
        res_json_obj["msg3"]["mac"].ToString(), DEBUG_LOG);
    
    print_debug_message("msg3.g_a.gx -> " + 
        res_json_obj["msg3"]["g_a"]["gx"].ToString(), DEBUG_LOG);

    print_debug_message("msg3.g_a.gy -> " + 
        res_json_obj["msg3"]["g_a"]["gy"].ToString(), DEBUG_LOG);

    print_debug_message("msg3.ps_sec_prop.sgx_ps_sec_prop_desc -> " + 
        res_json_obj["msg3"]["ps_sec_prop"]["sgx_ps_sec_prop_desc"].ToString(),
        DEBUG_LOG);

    print_debug_message("msg3.quote -> " + 
        res_json_obj["msg3"]["quote"].ToString(), DEBUG_LOG);
    
    print_debug_message("", DEBUG_LOG);
    
    response_json = res_json_obj.dump();

    return 0;
}


/* msg4を処理 */
int process_msg4(sgx_enclave_id_t eid,
    std::string request_json, std::string &error_message)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Process msg4", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    ra_msg4_t msg4;
    json::JSON req_json_obj = json::JSON::Load(request_json);
    size_t tmpsz;

    /* RAコンテキストをデコード */
    std::string ra_ctx_str = std::string(base64_decode<char, char>(
        (char*)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

    /* msg4をJSONから抽出 */
    sgx_ra_context_t ra_ctx;
    
    try
    {
        ra_ctx = std::stoi(ra_ctx_str);
    }
    catch(...)
    {
        error_message = "Invalid RA context format.";
        print_debug_message(error_message, ERROR);
        return -1;
    }

    std::string ra_status_str = std::string(base64_decode<char, char>(
        (char*)req_json_obj["msg4"]["status"].ToString().c_str(), tmpsz));

    if(ra_status_str == "Trusted") msg4.status = Trusted;
    else if(ra_status_str == "Conditionally_Trusted")
        msg4.status = Conditionally_Trusted;
    else if(ra_status_str == "NotTrusted") msg4.status = NotTrusted;
    else
    {
        error_message = "Unexpected status in msg4.";
        print_debug_message(error_message, ERROR);
        return -1;
    }

    memcpy(msg4.description, base64_decode<char, char>(
        (char*)req_json_obj["msg4"]["description"].ToString().c_str(), tmpsz), 512);
    
    memcpy(&msg4.pib, base64_decode<uint8_t, char>(
        (char*)req_json_obj["msg4"]["pib"].ToString().c_str(), tmpsz),
            SGX_PLATFORM_INFO_SIZE);

    print_debug_message(msg4.description, INFO);

    std::string message;
    
    if(msg4.status == NotTrusted)
    {
        /* RA拒絶時はRAコンテキストを削除 */
        sgx_status_t retval;
        ecall_ra_close(eid, &retval, ra_ctx);
        
        message = "RA is refused by SP. RA context: ";
        message += std::to_string(ra_ctx);
        print_debug_message(message, INFO);
    }
    else
    {
        message = "RA is accepted by SP. RA context: ";
        message += std::to_string(ra_ctx);
        print_debug_message(message, INFO);
    }

    print_debug_message("", INFO);

    return 0;
}


/* SPから受信した2値をEnclave内で復号し加算して結果を返却 */
int sample_addition(sgx_enclave_id_t eid, std::string request_json,
    std::string &response_json, std::string error_message)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Sample Addition", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj= json::JSON::Load(request_json);

    uint8_t *cipher1, *cipher2;
    uint8_t *iv, *tag1, *tag2;
    size_t cipher1_len, cipher2_len, tmpsz;
    sgx_ra_context_t ra_ctx;

    ra_ctx = std::stoi(base64_decode<char, char>
        ((char*)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

    cipher1 = base64_decode<uint8_t, char>
        ((char*)req_json_obj["cipher1"].ToString().c_str(), cipher1_len);
    
    cipher2 = base64_decode<uint8_t, char>
        ((char*)req_json_obj["cipher2"].ToString().c_str(), cipher2_len);

    iv = base64_decode<uint8_t, char>
        ((char*)req_json_obj["iv"].ToString().c_str(), tmpsz);

    tag1 = base64_decode<uint8_t, char>
        ((char*)req_json_obj["tag1"].ToString().c_str(), tmpsz);
    
    tag2 = base64_decode<uint8_t, char>
        ((char*)req_json_obj["tag2"].ToString().c_str(), tmpsz);
    
    sgx_status_t status, retval;
    uint8_t *result, *iv_result, *tag_result;
    size_t result_len;

    iv_result = new uint8_t[12]();
    tag_result = new uint8_t[16]();

    /* 結果用バッファサイズは決め打ち。uint64_t同士の加算であるため、
     * 本来は10バイトもあれば十分である。
     * 行儀よくやるのであれば、サイズ把握用の関数を用意するのが良いが、
     * 事実上二重処理になるため、行う処理の重さと相談する */
    result = new uint8_t[32]();

    /* ECALLを行い秘密計算による加算を実行 */
    print_debug_message("Invoke ECALL for addition.", DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    status = ecall_sample_addition(eid, &retval, ra_ctx, cipher1,
        cipher1_len, cipher2, cipher2_len, iv, tag1, tag2, 
        result, &result_len, iv_result, tag_result);

    if(status != SGX_SUCCESS)
    {
        error_message = "Failed to complete sample addition ECALL.";   
        return -1;
    }

    json::JSON res_json_obj;

    res_json_obj["cipher"] = std::string(
        base64_encode<char, uint8_t>(result, result_len));

    res_json_obj["iv"] = std::string(
        base64_encode<char, uint8_t>(iv_result, 12));

    res_json_obj["tag"] = std::string(
        base64_encode<char, uint8_t>(tag_result, 16));

    response_json = res_json_obj.dump();

    return 0;
}


/* SPから受信したRAコンテキストのRAを破棄 */
void destruct_ra_context(sgx_enclave_id_t eid, std::string request_json)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Destruct RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj= json::JSON::Load(request_json);
    size_t tmpsz;

    std::string ra_ctx_str = std::string(base64_decode<char, char>(
    (char*)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

    sgx_ra_context_t ra_ctx;
    sgx_status_t retval;
    
    try
    {
        ra_ctx = std::stoi(ra_ctx_str);
    }
    catch(...)
    {
        print_debug_message("Invalid RA context format.", ERROR);
        return;
    }

    ecall_ra_close(eid, &retval, ra_ctx);

    print_debug_message("Destructed following RA context -> ", INFO);
    print_debug_message(ra_ctx_str, INFO);
    print_debug_message("", INFO);

    return;
}


/* Enclaveの初期化 */
int initialize_enclave(sgx_enclave_id_t &eid)
{
    /* LEはDeprecatedになったので、起動トークンはダミーで代用する */
    sgx_launch_token_t token = {0};

    /* 起動トークンが更新されているかのフラグ。Deprecated。 */
    int updated = 0;

    /* 署名済みEnclaveイメージファイル名 */
    std::string enclave_image_name = "enclave.signed.so";

    sgx_status_t status;

    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
	void* enclave_ex_p[32] = {0};

	enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = &us_config;

    /* 
     * Switchless Callが有効化されたEnclaveの作成。
     * NULLの部分はEnclaveの属性（sgx_misc_attribute_t）が入る部分であるが、
     * 不要かつ省略可能なのでNULLで省略している。
     */
    status = sgx_create_enclave_ex(enclave_image_name.c_str(), SGX_DEBUG_FLAG,
                &token, &updated, &eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, 
                    (const void**)enclave_ex_p);

    if(status != SGX_SUCCESS)
	{
		/* error_print.cppで定義 */
		print_sgx_status(status);
		return -1;
	}

    return 0;
}


int main()
{
    print_debug_message("", INFO);
    print_debug_message("Launched ISV's untrusted application.", INFO);

    sgx_enclave_id_t eid = -1;

    /* Enclaveの初期化 */
    if(initialize_enclave(eid) < 0)
	{
		std::cerr << "App: fatal error: Failed to initialize Enclave.";
		std::cerr << std::endl;
		exit(1);
    }
    
    /* サーバの起動（RAの実行） */
    std::thread srvthread(server_logics, eid);

    /* サーバ停止準備。実際の停止処理は後ほど実装 */
    srvthread.join();
}