#ifndef _MY_PUB_H_
#define _MY_PUB_H_
#include "log.h"
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/tcp.h>
void procperr(int signum) {
  if (signum == SIGPIPE)
    LOG_E("fatal error sigpipe, port error[%d-%s]", errno, strerror(errno));
}
char *buffer2hex(char msg[], int len) {
  static char _hexbuffer[1024 * 3];
  len = len >= 1024 ? 1023 : len;
  for (int i = 0; i < len; i++) {
    sprintf(_hexbuffer + 3 * i, "%02X ", (unsigned char)(msg[i]));
  }
  return _hexbuffer;
}
void encodebuffer(unsigned char *msg, int len, unsigned char key) {
  if (key == 0)
    return;
  for (int i = 0; i < len; i++)
    msg[i] = msg[i] ^ key;
}
void encodebuffer(char *msg, int len, unsigned char key) {
  return encodebuffer((unsigned char *)msg, len, key);
}
bool getsockaddrfromhost(char *msg, unsigned char bytes, sockaddr_in &serv) {
  struct hostent *host;
  char hostname[256];
  memcpy(hostname, msg, bytes);
  hostname[bytes] = '\0';
  LOG_I("hostname: %s", hostname);
  if ((host = gethostbyname(hostname)) == NULL)
    return false;
  memcpy(&serv.sin_addr.s_addr, host->h_addr, 4);
  // printf("host address: %x\n", serv.sin_addr.s_addr);
  return true;
}
void setnonblock(int fd) {
  int flag = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}
void setblock(int fd) {
  int flag = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, flag ^ O_NONBLOCK);
}
struct timeval _tv;
void settimeout(int sock, int second, int flag = -1) {
  _tv.tv_sec = second;
  _tv.tv_usec = 0;
  if (flag != -1) {
    setsockopt(sock, SOL_SOCKET, flag, (const char *)&_tv, sizeof(timeval));
    return;
  }
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&_tv,
             sizeof(timeval));
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&_tv,
             sizeof(timeval));
}
#define setsendtimeout(fd, sec) settimeout(fd, sec, SO_SNDTIMEO)
#define setrecvtimeout(fd, sec) settimeout(fd, sec, SOL_RCVTIMEO);

void setsockreuse(int fd) {
  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}


void setsockkeepalive(int fd, int sec=600, int interval=30, int count=2){ 
  int opt=1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
  setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &sec, sizeof(sec));
  setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
  setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &count, sizeof(count));
}

#endif
