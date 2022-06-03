#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "myerr.h"
#include "pub.h"
extern int errno;
#include "xevent.h"
#include "tsockproc.h"

const char* c_keyword_apply="APPLY";
const char* c_keyword_close="CLOSE";
const char* c_keyword_reg = "REG--";
const int c_keyword_len = 5;
const int c_username_max = 50;
const unsigned char  c_oper_size = 64;
const char* reguser = "";

unsigned char encodekey = 0;

const int MAXFD = 4096;
int fdmap[MAXFD];
struct tsock tsocks[MAXFD];
struct pairfd {
    int fd;
    int dest;
    int hash;
    pairfd() {reset();}
    pairfd(int f, int h) {fd=f; dest=-1; hash=h;}
    bool used() {return (fd!=-1) && (dest!=-1);}
    bool unused() {return (fd!=-1)&&(dest==-1);}
    bool valid() {return fd!=-1;}
    bool samehash(int h) {return h==hash;}
    void setused(int f) {
      dest = f;
      if (fd!=-1) {fdmap[fd] = dest; tsocks[fd] = tsock(fd, dest, 2);}
      if (dest !=-1) {fdmap[dest] = fd; tsocks[dest] = tsock(dest, fd, 1);}
    }
    void setunused() {
      if (fd!=-1) {tsocks[fd].reset(); fdmap[fd] = -1;}
      if (dest!=-1) {tsocks[dest].reset();fdmap[dest] = -1;}
      dest = -1;
    }
    void reset() {
      setunused();  
      fd=-1; dest=-1; hash=0;
    }
};
struct pairfd pairfds[MAXFD];
int hash_username(const char* buffer){
   int n = *buffer < c_username_max ? *buffer : c_username_max;
   unsigned int h = 0;
   for (int i=1; i<n+1;i++){
	   h += h * 13 + buffer[i];
   }
   h ^= n;
   return int(h);
}
int apply_client_fd(int fd, const char* buffer){
   int h = hash_username(buffer);
   for(int i=0; i<(sizeof pairfds / sizeof(pairfd)); i++){
     if (pairfds[i].unused() && pairfds[i].samehash(h)){
        pairfds[i].setused(fd);
        fdmap[i] = fd;
        fdmap[fd] = i;
        LOG_R("apply serv client succ for %s <%d-%d>", buffer+1, fd, i);
        return i;
     }
   }
   LOG_R("apply serv client fail, no unused serv client for exist for %s<%d>", buffer+1, fd);
   return -1;
} 
void reg_client_fd(int fd, const char* buffer){
   int h = hash_username(buffer);
   pairfds[fd] = pairfd(fd, h);
   LOG_R("register service client for %s<%d>", buffer+1, fd);
}

int cb_proc_accept(int, int);
int cb_proc_conn(int, int);
int cb_proc_recv(int, int);
int cb_proc_send(int, int);
int cb_proc_error(int, int);

int cb_proc_accept(int srvfd, int filter){
    LOG_I("process accept: %d", srvfd);
    int clifd = -1; 
    struct sockaddr_in cli;
    unsigned int clilen=sizeof(cli);
    errno = 0;
    if ((clifd = accept(srvfd, (sockaddr*)&cli, &clilen)) < 0){
        LOG_E("accept[clifd-%d-clilen-%d] error[%d-%s], ignored!", clifd, clilen, errno, strerror(errno));
        char buffer[1024];
        int n = recv(srvfd, buffer, 1024, 0);
        LOG_E("clear read pool of accept: n=%d", n);
        return -1;
    }
    regxevent(clifd, xfilter_read, cb_proc_recv);
    fdmap[clifd] = -1;
    return 0;
}
int proc_close_s(int fd, int filter){
    unregxevent(fd);
    close(fd); 
    return 0;
}
int proc_close(int fd, int filter=-1){
    if (fd == -1) return 0;
    int dest = fdmap[fd];
    if (filter != -1) unregxevent(fd);
    fdmap[fd] = -1;
    pairfds[fd].reset();
    close(fd);
    return proc_close(dest, filter);
}

int cb_proc_recv(int fd, int filter){
  // first message
  if (fdmap[fd] == -1){
     char buffer[c_oper_size] = {0};
     int n = 0;
     if ( (n = recv(fd, buffer, c_oper_size, 0)) != c_oper_size) {
        LOG_E("proc first message return failed, length[%d], excpected[%d]", n, c_oper_size);
        proc_close_s(fd, filter);
     }
     encodebuffer((unsigned char*)buffer, n, encodekey);
     if (memcmp(buffer, c_keyword_apply, c_keyword_len) == 0){
        if (apply_client_fd(fd, buffer+c_keyword_len) == -1){
           char reply[]="out of stock";
           encodebuffer((unsigned char*)reply, sizeof reply, encodekey);
           write(fd, reply, sizeof reply);
           proc_close_s(fd, filter);
        }       
        else{
          int fwdfd = fdmap[fd];
          LOG_R("build channel succ: %d-%d", fd, fdmap[fd]); 
          char reply[]="channel-ok";
          encodebuffer((unsigned char*)reply, sizeof reply, encodekey);
          write(fd, reply, sizeof reply);
          write(fwdfd, reply, sizeof reply);
        }
     }       
     else if(memcmp(buffer, c_keyword_reg, c_keyword_len) == 0){
        reg_client_fd(fd, buffer+c_keyword_len);
        char reply[]="ok";
        encodebuffer((unsigned char*)reply, sizeof reply, encodekey);
        write(fd, reply, sizeof reply);
     }       
     else if(memcmp(buffer, c_keyword_close, c_keyword_len) == 0){
        LOG_R("recv close msg from client");
        proc_close_s(fd, filter);
     }       
     else{   
        buffer[n>c_oper_size?c_oper_size-1:n]=0; 
        LOG_E("recv msg from client(%d): %s-0x%s, keyword not right, close connect!", n, buffer, buffer2hex(buffer, n>32?32:n));
        proc_close_s(fd, filter);
     }   
  }
  else{
     int proc_result = recvsockandsend(tsocks[fd]);
     if (proc_result < 0){
        proc_close(fd, filter);
     }
     else if (proc_result == 1 && fdmap[fd]!=-1){
        LOG_I("switch %d-%d to send mode", fd, fdmap[fd]);
        unregxevent(fd, xfilter_read);
        regxevent(fdmap[fd], xfilter_write, cb_proc_send);
     }
     return proc_result;
  }
  return 0;   
}
int cb_proc_send(int fd, int filter){
  int dstfd = tsocks[fd].dstfd;
  int proc_result = sendsock(tsocks[dstfd]);
  if (proc_result < 0){
     proc_close(fd, filter);
  } else if  (proc_result == 0){
     LOG_I("switch %d-%d to recv mode", fdmap[fd], fd);
     unregxevent(fd, xfilter_write);
     regxevent(fdmap[fd], xfilter_read, cb_proc_recv);
  }
  return proc_result;
}

int main(int argc, char** argv){
    signal(SIGPIPE, procperr);
    signal(SIGCHLD, SIG_IGN);
    if (argc < 3){
        err_quit( "Usage: %s servport encodekey\n", argv[0]);
    }
    int srvfd, fsrvfd, clifd;
    if ((srvfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        err_sys("socket error");
    }
    char* servport = argv[1];
    encodekey = atoi(argv[2]);
    
    struct sockaddr_in serv = {0};
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(atoi(servport));

    setsockreuse(srvfd); 
    if (bind(srvfd, (const sockaddr*)&serv, sizeof(serv)) < 0) {
        err_sys("bind error");
    }
    if (listen(srvfd, 1) <0){
        err_sys("listen error");
    }
    LOG_R("start listen port %s ...", servport);

    initxevent();
    regxevent(srvfd, xfilter_read, cb_proc_accept);
    while(true){
       dispatchxevent(30);
    }
    return 0;
}

