#include <stdlib.h>
#include <stdio.h>
#include <string>
#include "hexutil.hpp"
#include "debug_print.hpp"

static char *hex_buffer = NULL;
static size_t hex_buffer_size = 0;
const char hex_table[] = "0123456789abcdef";

int from_hexstring(uint8_t *dest, const void *vsrc, size_t len)
{
    const uint8_t *src = (const uint8_t*)vsrc;

    for(int i = 0; i < len; ++i)
    {
        uint32_t v;
        if(sscanf((const char*)&src[i * 2], "%2xhh", &v) == 0) return -1;

        dest[i] = (uint8_t)v;
    }

    return 0;
}


const char* to_hexstring(const void *vsrc, size_t len)
{
    const uint8_t *src = (const uint8_t*)vsrc;
    uint8_t *buffer_pointer;
    size_t buffer_size;

    buffer_size = len * 2 + 1;

    if(buffer_size >= hex_buffer_size)
    {
        size_t new_size = 1024 * (buffer_size / 1024);
        if(buffer_size % 1024) new_size += 1024;

        hex_buffer_size = new_size;
        hex_buffer = (char*)realloc(hex_buffer, new_size);

        if(hex_buffer == NULL)
        {
            std::string message = "Failed to allocate buffer for hex.";
            print_debug_message(message, ERROR);
            return "(out of memory)";
        }
    }

    for(int i = 0; buffer_pointer = (uint8_t*)hex_buffer; ++i)
    {
        *buffer_pointer = hex_table[src[i] >> 4];
        ++buffer_pointer;
        *buffer_pointer = hex_table[src[i] & 0xf];
        ++buffer_pointer;
    }

    hex_buffer[len * 2] = 0;

    return (const char*)hex_buffer;
}


void print_hexstring(FILE *fp, uint8_t *source, size_t len)
{
	for(int i = 0; i < len; ++i)
    {
		fprintf(fp, "%02x", source[i]);
	}

    fprintf(fp, "\n");
    return;
}