#pragma once

#include <openssl/x509.h>

#include <string>
#include <map>
#include <vector>

#define IAS_SERVER_DEVELOPMENT 0
#define IAS_SERVER_PRODUCTION 1

#define IAS_SUBSCRIPTION_KEY_SIZE 32

/* IAS接続情報 */
#define IAS_SERVER_DEV_URL "api.trustedservices.intel.com/sgx/dev"
#define IAS_SERVER_PROD_URL "api.trustedservices.intel.com/sgx"
#define IAS_PORT 443

/* IASとの通信結果ステータスの定義 */
#define IAS_STATUS_QUERY_FAILED         0
#define IAS_STATUS_OK                   200
#define IAS_STATUS_BAD_REQUEST          400
#define IAS_STATUS_UNAUTHORIZED         401
#define IAS_STATUS_NOT_FOUND            404
#define IAS_STATUS_SERVER_ERROR         500
#define IAS_STATUS_SERVICE_UNAVAILABLE  503
#define IAS_STATUS_INTERNAL_ERROR       9999
#define IAS_STATUS_BAD_CERTIFICATE      9998
#define IAS_STATUS_BAD_SIGNATURE        9997

#define IAS_API_DEF_VERSION 4

class IAS_Communication
{
private:
    std::string server_url;
    std::string base_url;
    uint16_t api_version;
    uint32_t server_index;

    /* サブスクリプションキー用変数 */
    char primary_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE];
    char secondary_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE];

    /* サブスクリプションキーとXOR演算し秘匿するために用いる乱数 
     * [0][i]がプライマリ用、[1][i]がセカンダリ用*/
    char rn_for_xor[2][IAS_SUBSCRIPTION_KEY_SIZE];

    uint16_t server_port;
    X509_STORE *store;

    /* IASとの通信で使用するサブスクリプションキーのフラグ。
     * falseの時(プライマリ使用時)に失敗したらtrueにしてセカンダリで試行する */
    bool is_primary_failed = false;

    int set_subscription_key(int key_type, char *subscription_key);

public:
    IAS_Communication(int server_index,
        char *primary_subscription_key, char *secondary_subscription_key);
    ~IAS_Communication();

    std::string get_url_parts();

    std::string get_subscription_key();
    void set_is_primary_failed(bool flag) { this->is_primary_failed = flag; }
    bool get_is_primary_failed() { return this->is_primary_failed; }
    
    void set_cert_store(X509_STORE *store) { this->store = store; }
    X509_STORE* get_cert_store() { return this->store; }

    uint32_t sigrl(uint32_t gid, std::string &sigrl);
    uint32_t report(std::map<std::string, std::string> &payload,
            std::string &content);
};