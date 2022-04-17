//
// Created by nova on 4/11/22.
//

#ifndef BOOPKIT_COMMON_H
#define BOOPKIT_COMMON_H

#define MAX_BOOP_PRINTF_LOG 1024
#define BOOPKIT_RCE_DELIMITER "*~*"


extern int quiet;

void asciiheader();
void boopprintf(const char *__restrict __format, ...);

#endif  // BOOPKIT_COMMON_H
