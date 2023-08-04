#pragma once

#include <iostream>
#include <string>

/* ログ種別定義用の列挙型 */
typedef enum
{
    DEBUG_LOG = 0,
    INFO,
    ERROR
} MESSAGE_TYPE;

/* ログ種別に応じてログメッセージを標準出力 */
void print_debug_message(std::string message, MESSAGE_TYPE type);

/* ログ種別のタグのみを表示（改行無し）。
 * 他の標準出力ツールと組み合わせての使用を想定。 */
void print_log_type(MESSAGE_TYPE type);

/* バイナリチェック用標準出力に特化した関数 */
void print_debug_binary(std::string label,
    uint8_t *buf, size_t bufsz, MESSAGE_TYPE type);