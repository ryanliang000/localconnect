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
#include "error.h"
#include "xevent.h"
#include "tsockproc.h"
extern int errno;

const char* c_keyword_apply="APPLY";
const char* c_keyword_close="CLOSE";
const char* c_keyword_reg = "REG--";
const int c_keyword_len = 5;
const int c_username_max = 50;
const unsigned char  c_oper_size = 64;
const char* reguser = "";

unsigned char encodekey = 0;
struct sockaddr_in fserv;
unsigned int clilen = sizeof(fserv);

char* get_apply_buffer(){
    static char buffer[c_oper_size+1] = {0};
    if (buffer[0] == 0){
       memcpy(buffer, c_keyword_apply, c_keyword_len);
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
int cb_proc_error(int fd, int filter){
   unregxevent(fd);
   close(fd);
}
int cb_proc_accept(int srvfd, int filter){
    LOG_I("process accept: %d", srvfd);
    int clifd = -1, fsrvfd = -1, n=0; 
    struct sockaddr_in cli;
    if ((clifd = accept(srvfd, (sockaddr*)&cli, &clilen)) < 0){
        LOG_E("accept error[%d-%s], ignored!", errno, strerror(errno));
        return -1;
    }
    setsockkeepalive(clifd);
	// connect to forward server
	if ((fsrvfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
		LOG_E("forward socket init failed");
		close(clifd);
        return -1;
	}
    if (connect(fsrvfd, (sockaddr*)(&fserv), sizeof(fserv)) < 0){
		close(clifd);
		close(fsrvfd);
		LOG_E("connect to forward server failed <%d:%s>", errno, strerror(errno));
        return -1;
	}
    LOG_D("connect to remote %d", fsrvfd);
	// apply connect by user 
	char* applybuffer = get_apply_buffer();
	if (send(fsrvfd, applybuffer, c_oper_size, 0) != c_oper_size){
		LOG_E("send to remote error[%d-%s] occur, ignored!", errno, strerror(errno));
		close(clifd);
		close(fsrvfd);
		return -1;
	}
	// get reply from fserver
	char buffer[c_oper_size+1] = {0};
	if ((n=recv(fsrvfd, buffer, c_oper_size, 0)) < 0){
		LOG_E("recv[n=%d] from remote error[%d-%s]", n, errno, strerror(errno));
        close(clifd);
        close(fsrvfd);
		return -1;
	}
	encodebuffer((unsigned char*)buffer, c_oper_size, encodekey);
	char reply[]="channel-ok";
	if (memcmp(buffer, reply, sizeof reply) != 0){
		buffer[n]=0;
		LOG_E("recv msg from regsrv[%d]: %s-%s, connect bind failed!", n, buffer, buffer2hex(buffer, n>32?32:n));
		close(clifd);
		close(fsrvfd);
		return -1;
	}
    setnonblock(fsrvfd);
    tsocks[clifd] = tsock(clifd, fsrvfd, sock_client);
	tsocks[fsrvfd] = tsock(fsrvfd, clifd, sock_remote);
	regxevent(fsrvfd, xfilter_read, cb_proc_recv);
    regxevent(clifd, xfilter_read, cb_proc_recv);
    return 0;
}

int proc_close(int fd, int filter=-1){
	int dstfd = tsocks[fd].dstfd;
	if (fd != -1){unregxevent(fd); close(fd);}
	if (dstfd != -1){unregxevent(dstfd);close(dstfd);}
	tsocks[fd].reset();
	tsocks[dstfd].reset();
	LOG_R("connection [%d-%d] closed.", fd, dstfd);
}
int cb_proc_recv(int fd, int filter){
  int proc_result = recvsockandsend(tsocks[fd]);
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

int main(int argc, char** argv){
    signal(SIGPIPE, procperr);
    signal(SIGCHLD, SIG_IGN);
    if (argc < 6){
        err_quit( "Usage: %s forwardip forwardport servport username encodekey\n", argv[0]);
    }
    int srvfd, fsrvfd, clifd;
    if ((srvfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        err_sys("socket error");
    }
    char* servport = argv[3];
    char* username = argv[4];
	char* keycode = argv[5];
    reguser = username;

    struct sockaddr_in serv = {0};
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(atoi(servport));

    memset(&fserv, 0, sizeof(fserv));
    fserv.sin_family = AF_INET;
    fserv.sin_addr.s_addr = inet_addr(argv[1]);
    fserv.sin_port = htons(atoi(argv[2]));
    encodekey = atoi(keycode);

    setsockreuse(srvfd); 
    if (bind(srvfd, (const sockaddr*)&serv, sizeof(serv)) < 0) {
        err_sys("bind error");
    }
    if (listen(srvfd, 1) <0){
        err_sys("listen error");
    }
    LOG_R("start listen port %s for %s ...", servport, username);
    
	initxevent();
    regxevent(srvfd, xfilter_read, cb_proc_accept);
    while(true){
       dispatchxevent(30);
    }
    return 0;
}

