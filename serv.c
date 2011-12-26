/**
 * @fileoverview Serve a static resource in response to HTTP requests.
 *  Re-invent the wheel and use a custom tcp & http stack, since that
 *  lets us fully control the implementation.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 8192
#define MAX_CLIENTS 1024

struct clientState {
    struct sockaddr address;
    time_t update;
    int state;
};

/**
 * Client state information root.
 * Actual client state is malloc'ed to the heap.
 */
struct clientState** clients = NULL;

int sockaddr_equal(struct sockaddr* a, struct sockaddr* b) {
  // Sockaddr is defined to have 14 bytes of data.
  return a->sa_family == b->sa_family &&
      memcmp(a->sa_data, b->sa_data, sizeof(a->sa_data)) == 0;
}

struct clientState* get(struct sockaddr* remote) {
  int i = 0;
  struct clientState** free = NULL;
  struct clientState** lru = NULL;

  for (i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i] != NULL) {
      if (sockaddr_equal(&clients[i]->address, remote)) {
        return clients[i];
      } else if (lru == NULL || clients[i]->update < (*lru)->update) {
        lru = &clients[i];
      }
    } else if(clients[i] == NULL && free == NULL) {
      free = &clients[i];
    }
  }

  if (free != NULL) {
    *free = malloc(sizeof(struct clientState));
    (*free)->update = time(NULL);
    (*free)->address.sa_family = remote->sa_family;
    memcpy((*free)->address.sa_data, remote->sa_data, sizeof(remote->sa_data));
    (*free)->state = 0;
    return (*free);
  }

  (*lru)->update = time(NULL);
  (*lru)->address.sa_family = remote->sa_family;
  memcpy((*lru)->address.sa_data, remote->sa_data, sizeof(remote->sa_data));
  (*lru)->state = 0;
  return (*lru);
}

void release(struct sockaddr* remote) {
  int i;
  if (clients == NULL) {
    return;
  }

  for (i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i] != NULL && (remote == NULL ||
    	sockaddr_equal(&clients[i]->address, remote))) {
      free(clients[i]);
      clients[i] = NULL;
      return;
    }
  }
}

/**
 * The Handle.
 */
pcap_t* s;

/**
 * Make sure the handle is killed on quit, so we don't leave a mess behind.
 */
void leave() {
  release(NULL);
  free(clients);
  if (s != NULL) {
    pcap_close(s);
  }
  exit(0);
}

pcap_t* startup(char* dev, int port) {
  char errbuf[PCAP_ERRBUF_SIZE], filter[64];
  struct bpf_program fp;
  bpf_u_int32 net, mask;
  pcap_t *handle;
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s\n", dev);
    net = 0;
    mask = 0;
  }

  // Open the device.
  handle = pcap_open_live(
      dev,     // The device to open
      BUFSIZ,  // How much data to wait for
      1,       // Promiscuous?
      50,      // timeout in ms
      errbuf); // Error buffer.
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return NULL;
  }

  // Match packets meant for our desired port.  This rule may also match outbound traffic.
  sprintf(filter, "tcp dst port %d", port);
  if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
    fprintf(stderr, "Could not compile BPF: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return NULL;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Could not install BPF: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return NULL;
  }
  return handle;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  const struct ip *iphdr;
  u_int size_ip;
  char src[32],dest[32];

  iphdr = (struct ip*)(packet + 14);
  if (iphdr->ip_v != 4 || iphdr->ip_hl < 5) {
    return;
  }
  size_ip = iphdr->ip_hl * 4 + 14;

  inet_ntop(AF_INET, &iphdr->ip_dst, dest, 32);
  inet_ntop(AF_INET, &iphdr->ip_src, src, 32);

  printf("packet from %s to %s\n", src , dest);
}

int main(int argc, char *argv[]) {
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  int c;
  int port = 8888;
  struct clientState* client;
  dev = pcap_lookupdev(errbuf);
  clients = malloc(MAX_CLIENTS * sizeof(struct clientState*));

  // Register signal handlers for cleanup.
  signal(SIGINT, leave);
  signal(SIGTERM, leave);
  signal(SIGQUIT, leave);

  // Process Options.
  while ((c = getopt (argc, argv, "hd:p:")) != -1) {
    switch (c) {
      case 'd':
        dev = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'h':
      default:
        printf("Usage: %s [-d device] [-p port]\n", argv[0]);
        return 1;
    }
  }

  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	return 2;
  }
  printf("Using Device %s\n", dev);
  s = startup(dev, port);
  
  if (s != NULL) {
    if (pcap_loop(s, 0, got_packet, NULL) != 0) {
      fprintf(stderr, "Processing unsuccessful: %s\n", pcap_geterr(s));
    }
    pcap_close(s);
  }
  return 0;
}
