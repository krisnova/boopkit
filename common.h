//
// Created by nova on 4/11/22.
//

#ifndef BOOPKIT_COMMON_H
#define BOOPKIT_COMMON_H

#include <stddef.h>

#define MAX_BOOP_PRINTF_LOG 1024
#define BOOPKIT_RCE_DELIMITER "_X_"

extern int quiet;

void asciiheader();
void boopprintf(const char *__restrict __format, ...);
char *base64_encode(const unsigned char *data, size_t input_length,
                    size_t *output_length);
unsigned char *base64_decode(const unsigned char *data, size_t input_length,
                             size_t *output_length);

void build_decoding_table();
void base64_cleanup();

#endif  // BOOPKIT_COMMON_H
