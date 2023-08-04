#pragma once

#include <stdio.h>

int from_hexstring(uint8_t *dest, const void *vsrc, size_t len);
const char* to_hexstring(const void *vsrc, size_t len);
void print_hexstring(FILE *fp, uint8_t *source, size_t len);