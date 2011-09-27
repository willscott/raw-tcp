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
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 8888
#define BUFFER_SIZE 8192

struct clientState {
    int fd;
};

/**
 * The Socket.
 */
int s;

/**
 * Make sure the socket is killed on quit, so we don't leave a mess behind.
 */
void leave() {
  close(s);
  exit(0);
}

int main() {
  struct sockaddr_in sin, cin;
  socklen_t b;
  struct linger linger;
  int i;
  char buffer[BUFFER_SIZE];

  // Register signal handlers for cleanup.
  signal(SIGINT, leave);
  signal(SIGTERM, leave);
  signal(SIGQUIT, leave);

  // Setup socket data structures.
  bzero((char *)&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(PORT);

  // Accept raw packets.
  if ((s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
    perror("socket creation failed.");
    exit(1);
  }

  // Allow socket reuse.
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &b, sizeof(b));
  // Close immediately when we ask.
  linger.l_onoff = 0;
  setsockopt(s, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
  // Bind the socket.
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("Could not bind socket.");
    exit(1);
  }

  printf("Listening on port %d.", PORT);
  fflush(stdout);

  while(1) {
    i = recvfrom(s, buffer, sizeof(buffer), 0,
         (struct sockaddr *)&cin, &b);
    buffer[i] = '\0';
    printf("\n%s:%d -> %s", inet_ntoa(cin.sin_addr),
        ntohs(cin.sin_port), buffer);
    fflush(stdout);
  }

  exit(0);
}
