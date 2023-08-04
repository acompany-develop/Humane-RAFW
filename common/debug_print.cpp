#include "debug_print.hpp"
#include "hexutil.hpp"


/* ログ種別に応じてログメッセージを標準出力 */
void print_debug_message(std::string message, MESSAGE_TYPE type)
{
    if(type == DEBUG_LOG)
    {
        std::cout << "\033[32mDEBUG: \033[m" << message << std::endl;
    }
    else if(type == ERROR)
    {
        std::cerr << "\033[31mERROR: \033[m" << message << std::endl;
    }
    else
    {
        std::cout << "\033[36m INFO: \033[m" << message << std::endl;
    }
}

/* ログ種別を表示（改行無し） */
void print_log_type(MESSAGE_TYPE type)
{
    if(type == DEBUG_LOG)
    {
        std::cout << "\033[32mDEBUG: \033[m";
    }
    else if(type == ERROR)
    {
        std::cerr << "\033[31mERROR: \033[m";
    }
    else
    {
        std::cout << "\033[36m INFO: \033[m";
    }
}


void print_debug_binary(std::string label,
    uint8_t *buf, size_t bufsz, MESSAGE_TYPE type)
{
    print_debug_message(label + " -> ", DEBUG_LOG);
    print_log_type(DEBUG_LOG);
    print_hexstring(stdout, buf, bufsz);
    print_debug_message("", type);
}