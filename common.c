// Copyright © 2022 Kris Nóva <kris@nivenly.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
// ████╗  ██║██╔═████╗██║   ██║██╔══██╗
// ██╔██╗ ██║██║██╔██║██║   ██║███████║
// ██║╚██╗██║████╔╝██║╚██╗ ██╔╝██╔══██║
// ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
// ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
//
// [common.c]

#include "common.h"

#include <stdarg.h>
#include <stdio.h>

//#include "boopkit.h"

int quiet = 0;

void boopprintf(const char *format, ...) {
  if (quiet) {
    return;
  }
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

// asciiheader is the main runtime banner.
void asciiheader() {
  if (quiet) {
    return;
  }
  printf(
      "\n================================================================\n");
  printf("\n");
  printf("    ██████╗  ██████╗  ██████╗ ██████╗ ██╗  ██╗██╗████████╗\n");
  printf("    ██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║╚══██╔══╝\n");
  printf("    ██████╔╝██║   ██║██║   ██║██████╔╝█████╔╝ ██║   ██║   \n");
  printf("    ██╔══██╗██║   ██║██║   ██║██╔═══╝ ██╔═██╗ ██║   ██║   \n");
  printf("    ██████╔╝╚██████╔╝╚██████╔╝██║     ██║  ██╗██║   ██║   \n");
  printf("    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝   \n");
  printf("    Author: Kris Nóva <kris@nivenly.com> Version %s\n", VERSION);
  printf("    \n");
  printf("    IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE \n");
  printf("    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, \n");
  printf("    EXEMPLARY, OR CONSEQUENTIAL DAMAGES.");
  printf("    \n\n");
  printf("    DO NOT ATTEMPT TO USE THE TOOLS TO VIOLATE THE LAW.\n");
  printf("    THE AUTHOR IS NOT RESPONSIBLE FOR ANY ILLEGAL ACTION.\n");
  printf("    MISUSE OF THE SOFTWARE, INFORMATION, OR SOURCE CODE\n");
  printf("    MAY RESULT IN CRIMINAL CHARGES.\n");
  printf("    \n");
  printf("    Use at your own risk.\n");
  printf("\n");
  printf("================================================================\n");
}
