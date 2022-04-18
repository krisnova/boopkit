//
// Created by nova on 4/11/22.
//

#ifndef BOOPKIT_COMMON_H
#define BOOPKIT_COMMON_H

#define BOOPKIT_RCE_DELIMITER "_X_"

extern int quiet;

// VERSION is the semantic version of the program
#define VERSION "1.2.0"

void asciiheader();
void boopprintf(const char *__restrict __format, ...);

#endif  // BOOPKIT_COMMON_H
