/**
 * @fileoverview Serve a static resource in response to HTTP requests, and then
 *  keep the connection open until infeasable.  Sadly, we re-invent the wheel
 *  and create our own tcp & http stack, since want to have them act subtly
 *  different from the normal implementation.
 */

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 8888
#define MAX_PENDING 10

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
  struct sockaddr_in sin;
  struct linger linger;
  struct pollfd fds[MAX_PENDING + 1];
  struct clientState states[MAX_PENDING];
  int sockopt, b, i, numcon = 0;

  // Register signal handlers for cleanup.
  signal(SIGINT, leave);
  signal(SIGTERM, leave);
  signal(SIGQUIT, leave);

  // Aetup socket data structures.
  bzero((char *)&sin, sizeof(sin));
  bzero(states, MAX_PENDING * sizeof(struct clientState));
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
  // Mark socket non-blocking.
  if ((sockopt = fcntl(s, F_GETFL)) < 0) {
    perror("Could not get file control settings for socket.");
    exit(1);
  }
  if ((fcntl(s, F_SETFL, (sockopt | O_NONBLOCK))) < 0) {
    perror("Could not set socket nonblocking.");
    exit(1);
  }
  // Bind the socket.
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("Could not bind socket.");
    exit(1);
  }
  listen(s, MAX_PENDING);

  while(1) {
    fds[0].fd = s;
    fds[0].events = POLLIN;
    for (i = 0; i < numcon; i++) {
      fds[i+1].fd = states[i].fd;
      fds[i+1].events = POLLIN;
    }

    poll(fds, numcon + 1, 120 * 1000);

    // Handle incoming packets.
    for (i = 0; i < numcon; i++) {
    }

    // Handle new connections.
    if (fds[0].revents != 0 && numcon < MAX_PENDING) {
      if ((states[numcon].fd = accept(s, NULL, NULL)) < 0) {
        perror("Could not accept client.");
        exit(1);
      }
      if ((sockopt = fcntl(states[numcon].fd, F_GETFL)) < 0) {
        perror("Could not get file control settings for client.");
        exit(1);
      }
      if (fcntl(states[numcon].fd, F_SET_FL, (sockopt | O_NONBLOCK)) < 0) {
        perror("Could not set client file non-blocking.");
        exit(1);
      }
      numcon++;
    }
  }

  exit(0);
}
