/* msg4（アテステーションステータス）関係の構造体等を定義 */
#pragma once

#include <sgx_quote.h>


typedef enum
{
    NotTrusted = 0, //信頼不可能
    Conditionally_Trusted, //便宜上信頼可能と見なす
    Trusted //信頼可能
} attestation_status_t;

typedef struct _ra_msg4_struct
{
    attestation_status_t status;
    char description[512];
    sgx_platform_info_t pib; //Platform Info Blob
} ra_msg4_t;