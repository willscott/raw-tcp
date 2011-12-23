/**
 * @fileoverview Serve a static resource in response to HTTP requests, and then
 *  keep the connection open until infeasable.  Re-invent the wheel
 *  and create a custom tcp & http stack, since that lets them act subtly
 *  different from standard implementations.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
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
 * The Socket.
 */
int s;

/**
 * Make sure the socket is killed on quit, so we don't leave a mess behind.
 */
void leave() {
  release(NULL);
  free(clients);  
  close(s);
  exit(0);
}

int checkip(char* packet) {
  int ip_hdr_len = 0;
  unsigned int source_address = 0;
  unsigned short source_port, destination_port;
  struct in_addr src;

  // IPv4.
  if ((packet[0] & (16 + 32 + 64 + 128)) != 64) {
    return 0;
  }
  // TCP.
  if (packet[9] != 6) {
    return 0;
  }

  source_address = packet[12] << 24 + packet[13] << 16 + packet[14] << 8 + packet[15];
  ip_hdr_len = 4 * (packet[0] & (1 + 2 + 4 + 8));

  source_port = packet[ip_hdr_len] << 8 + packet[ip_hdr_len + 1];
  destination_port = packet[ip_hdr_len + 2] << 8 + packet[ip_hdr_len + 3];

  printf("packet from %d:%d to %d\n",source_address , source_port, destination_port); 

  return 1;
}

void tcpalyze(char* packet) {
  printf("\n");
}

int main() {
  struct sockaddr_storage cin;
  struct clientState* client;
  socklen_t b = sizeof(cin);
  int i;
  char buffer[BUFFER_SIZE];
  clients = malloc(MAX_CLIENTS * sizeof(struct clientState*));
  

  // Register signal handlers for cleanup.
  signal(SIGINT, leave);
  signal(SIGTERM, leave);
  signal(SIGQUIT, leave);

  // Accept raw packets.
  if ((s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
    perror("socket creation failed.");
    exit(1);
  }

  // Include IP Header
  i = 1;
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) < 0) {
    perror("Could not include ip headers.");
    exit(1);
  }
  // Allow socket reuse.
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &b, sizeof(b));


  while(1) {
    i = recvfrom(s, buffer, sizeof(buffer), 0, (struct sockaddr*)&cin, &b);
    buffer[i] = '\0';
    if (!checkip(buffer)) {
      continue;
    }
    // client = get((struct sockaddr*)&cin);
    fflush(stdout);
  }

  exit(0);
}
