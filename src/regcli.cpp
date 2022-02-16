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
#include "xevent.h"
#include "tsockproc.h"
#include "pthread.h"
extern int errno;
#define nullptr NULL

const char* c_keyword_apply="APPLY";
const char* c_keyword_close="CLOSE";
const char* c_keyword_reg = "REG--";
const int c_keyword_len = 5;
const int c_username_max = 50;
const unsigned char  c_oper_size = 64;
const char* reguser = "";

unsigned char encodekey = 0;
struct sockaddr_in fserv = {0}, regserv = {0};
unsigned int clilen = sizeof(fserv);
bool reconnect = false;
const int c_regcli_max_wait = 2;
const int c_regcli_max = 10;
int regcli_curr = 0;
int regcli_wait = 0;

char* get_apply_buffer(){
    static char buffer[c_oper_size+1] = {0};
    if (buffer[0] == 0){
       memcpy(buffer, c_keyword_apply, c_keyword_len);
       encodebuffer((unsigned char*)buffer, c_oper_size, encodekey);
       char len = strlen(reguser) < c_username_max ? strlen(reguser) : c_username_max;
       buffer[c_keyword_len] = len;
       memcpy(buffer + c_keyword_len + 1, reguser, len);
       encodebuffer((unsigned char*)buffer, c_keyword_len + 1 + len, encodekey); 
    }
    return buffer;
}
char* get_reg_buffer(){
    static char buffer[c_oper_size+1] = {0};
    if (buffer[0] == 0){
       memcpy(buffer, c_keyword_reg, c_keyword_len);
       char len = strlen(reguser) < c_username_max ? strlen(reguser) : c_username_max;
       buffer[c_keyword_len] = len;
       memcpy(buffer + c_keyword_len + 1, reguser, len);
       encodebuffer((unsigned char*)buffer, c_oper_size, encodekey);
    }
    return buffer;
}
const int MAXFD = 4096;
struct tsock tsocks[MAXFD];

int cb_proc_accept(int, int);
int cb_proc_recv(int, int);
int cb_proc_send(int, int);
void try_regclient();
int cb_proc_error(int fd, int filter){
   unregxevent(fd);
   close(fd);
   regcli_curr--;
   regcli_wait--;
   try_regclient();
   return 0;
}

int cb_proc_accept(int srvfd, int filter){
    LOG_I("process accept: %d", srvfd);
	int fsrvfd = -1, n=0; 
	// get reply from fserver
	char buffer[c_oper_size+1] = {0};
	if ((n=recv(srvfd, buffer, c_oper_size, 0)) < 0){
		LOG_E("recv[n=%d] from remote error[%d-%s]", n, errno, strerror(errno));
		cb_proc_error(srvfd, filter);
		return -1;
	}
	encodebuffer((unsigned char*)buffer, c_oper_size, encodekey);
	char reply[]="channel-ok";
	if (memcmp(buffer, reply, sizeof reply) != 0){
		buffer[n]=0;
		LOG_E("recv msg from regsrv[%d]: %s-%s, connect bind failed!", n, buffer, buffer2hex(buffer, n>32?32:n));
		cb_proc_error(srvfd, filter);
		return -1;
	}
	
    LOG_I("accept ok, will connect to forward");	
	// connect to forward server
	if ((fsrvfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
		LOG_E("forward socket init failed");
		cb_proc_error(srvfd, filter);
        return -1;
	}
    if (connect(fsrvfd, (sockaddr*)(&fserv), sizeof(fserv)) < 0){
		close(fsrvfd);
		cb_proc_error(srvfd, filter);	
		LOG_E("connect to forward server failed <%d:%s>", errno, strerror(errno));
        return -1;
	}
    LOG_D("connected to forward %d", fsrvfd);
    tsocks[srvfd] = tsock(srvfd, fsrvfd, sock_client);
	tsocks[fsrvfd] = tsock(fsrvfd, srvfd, sock_remote);
	unregxevent(srvfd);
    setsockkeepalive(fsrvfd, 120);
    setsockkeepalive(srvfd, 120);
	regxevent(fsrvfd, xfilter_read, cb_proc_recv);
    regxevent(srvfd, xfilter_read, cb_proc_recv);
    LOG_R("channel build succ for %d-%d", srvfd, fsrvfd);
    regcli_wait--;
    try_regclient();
    return 0;
}

int proc_close(int fd, int filter=-1){
	int dstfd = tsocks[fd].dstfd;
	if (fd != -1){unregxevent(fd); close(fd); tsocks[fd].reset();}
	if (dstfd != -1){unregxevent(dstfd);close(dstfd); tsocks[dstfd].reset();}
	LOG_R("connection [%d-%d] closed.", fd, dstfd);
	regcli_curr--;
    try_regclient();
}
int cb_proc_recv(int fd, int filter){
  int dstfd = tsocks[fd].dstfd;
  if (dstfd == -1){
	  return 0;
  }
  int proc_result = recvsockandsendencoded(tsocks[fd], encodekey);
  if (proc_result < 0){
    proc_close(fd, filter);
  }
  else if (proc_result == 1 && tsocks[fd].dstfd!=-1){
    LOG_I("switch %d-%d to send mode", fd, tsocks[fd].dstfd);
    unregxevent(fd, xfilter_read);
    regxevent(tsocks[fd].dstfd, xfilter_write, cb_proc_send);
  }
  return proc_result;
}
int cb_proc_send(int fd, int filter){
  int proc_result = sendsock(tsocks[fd]);
  if (proc_result < 0){
     proc_close(fd, filter);
  } else if  (proc_result == 0){
     LOG_I("switch %d-%d to recv mode", tsocks[fd].dstfd, fd);
     unregxevent(fd, xfilter_write);
     regxevent(tsocks[fd].dstfd, xfilter_read, cb_proc_recv);
  }
  return proc_result;
}

void regclient(){
  int regfd = -1, n=0;
  bool reinit = false;
  while(true){
    if (reinit){
       LOG_R("wait for reconnect to reg server");
       sleep(10);
    }
    reinit = true;
    // connect to forward server
    if ((regfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        LOG_E("regfd socket init failed");
        continue;
    }       
    if (connect(regfd, (sockaddr*)(&regserv), sizeof(regserv)) < 0){
       close(regfd);
       LOG_E("connect to reg server failed <%d:%s>", errno, strerror(errno));
       continue;
    }       
    LOG_D("connected to regserver[%d]", regfd); 
    // apply connect by user 
    char* applybuffer = get_reg_buffer();
    if (send(regfd, applybuffer, c_oper_size, 0) != c_oper_size){
       LOG_E("send to remote error[%d-%s] occur, ignored!", errno, strerror(errno));
       close(regfd);
       continue;
    }       
    // get reply from fserver 
    char buffer[c_oper_size+1] = {0};
    if ((n=recv(regfd, buffer, c_oper_size, 0)) < 0){
        LOG_E("recv[n=%d] from remote error[%d-%s]", n, errno, strerror(errno));
        close(regfd);
        continue;
    }       
    encodebuffer((unsigned char*)buffer, c_oper_size, encodekey);
    char reply[]="ok";
    if (memcmp(buffer, reply, sizeof reply) != 0){
        buffer[n]=0;
        LOG_E("recv msg from regsrv[%d]: %s-%s, connect bind failed!", n, buffer, buffer2hex(buffer, n>32?32:n));
        close(regfd);
        continue;
    }
    settimeout(regfd, 360);
    setsockkeepalive(regfd, 120);
    tsocks[regfd] = tsock(regfd, -1, sock_server);
    regxevent(regfd, xfilter_read, cb_proc_accept);
    LOG_R("reg client %d succ", regfd);
    break;
  }
}

void* regclient_thread(void* p){
  pthread_detach(pthread_self());
  regclient();
  return p;
}
pthread_t threads[c_regcli_max+1];
void try_regclient(){
  while(regcli_wait < c_regcli_max_wait && regcli_curr < c_regcli_max){
    void* pArgs = &threads[regcli_curr];
    if (pthread_create(&threads[regcli_curr], NULL, regclient_thread, pArgs)){
       LOG_R("thread create failed");
       sleep(1);
       continue;
    }
    regcli_curr++;
    regcli_wait++;
  }
  LOG_R("regclient: curr-%d, wait-%d", regcli_curr, regcli_wait);
}
int main(int argc, char** argv){
    signal(SIGPIPE, procperr);
    signal(SIGCHLD, SIG_IGN);
#ifndef REGFIX    
    if (argc < 6){
        err_quit( "Usage: %s regserver regserverport username encodekey forwardip forwardport\n", argv[0]);
    }
	char* regserver = argv[1];
	char* regserverport = argv[2];
    char* username = argv[3];
	char* keycode = argv[4];
	char* forwardip = argv[5];
	char* forwardport = argv[6];
#else
    if (argc < 2){
        err_quit( "Usage: %s username\n", argv[0]);
    }
    const char* regserver = "127.0.0.18";
    const char* regserverport = "8080";
    char* username = argv[1];
    const char* keycode = "80";
    const char* forwardip = "127.0.0.1";
    const char* forwardport = "22";
#endif

    int srvfd, fsrvfd, clifd, regfd;
    reguser = username;
    
	regserv.sin_family = AF_INET;
    regserv.sin_addr.s_addr = inet_addr(regserver);
    regserv.sin_port = htons(atoi(regserverport));
    fserv.sin_family = AF_INET;
    fserv.sin_addr.s_addr = inet_addr(forwardip);
    fserv.sin_port = htons(atoi(forwardport));
    encodekey = atoi(keycode);
    int n = 0;

	initxevent();
    try_regclient();
	LOG_R("start to wait channel message");
	while(true){
		dispatchxevent(30);
	}

    return 0;
}

