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

#include <stdio.h>
#include <string.h>
#include "common.h"

int quiet = 0;

void boopprintf (const char *format, ...) {
  if (quiet) {
    return;
  }
  va_list args;
  va_start( args, format );
  vprintf( format, args );
  va_end( args );
}

// asciiheader is the main runtime banner.
void asciiheader() {
  if (quiet) {
    return;
  }
  printf("\n\n");
  printf("   ██████╗  ██████╗  ██████╗ ██████╗ ██╗  ██╗██╗████████╗\n");
  printf("   ██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║╚══██╔══╝\n");
  printf("   ██████╔╝██║   ██║██║   ██║██████╔╝█████╔╝ ██║   ██║   \n");
  printf("   ██╔══██╗██║   ██║██║   ██║██╔═══╝ ██╔═██╗ ██║   ██║   \n");
  printf("   ██████╔╝╚██████╔╝╚██████╔╝██║     ██║  ██╗██║   ██║   \n");
  printf("   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝   \n");
  printf("\n\n");
}

