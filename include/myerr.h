/*
 * Copyright (c) 1996 W. Richard Stevens.  All rights reserved.
 * Permission to use or modify this software and its documentation only for
 * educational purposes and without fee is hereby granted, provided that
 * the above copyright notice appear in all copies.  The author makes no
 * representations about the suitability of this software for any purpose.
 * It is provided "as is" without express or implied warranty.
 */

#ifndef _MY_ERR_H_
#define _MY_ERR_H_

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXLINE 4096
static void err_doit(int, const char *, va_list);

// nonfatal error related to system call, print a msg and return.
void err_ret(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  err_doit(1, fmt, ap);
  va_end(ap);
  printf("test");
  return;
}

// fatal error related to a system call, print a msg and teminate.
void err_sys(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  err_doit(1, fmt, ap);
  va_end(ap);
  exit(1);
  ;
}

// fatal error related to a system call, print a msg, dump core and terminate
void err_dump(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  err_doit(1, fmt, ap);
  va_end(ap);
  abort(); // dump core and terminate
  exit(1); // shoudn't get here
}

// nonfatal error related to a system call, print a msg and return
void err_msg(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  err_doit(0, fmt, ap);
  va_end(ap);
  return;
}

// fatal error related to a system call, print a msg and terminate
void err_quit(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  err_doit(0, fmt, ap);
  va_end(ap);
  exit(1);
}

// print a message and return to caller. caller specifies errnoflag
static void err_doit(int errnoflag, const char *fmt, va_list ap) {
  int errno_save;
  char buf[MAXLINE];

  errno_save = errno; // value called might want printed
  vsprintf(buf, fmt, ap);
  if (errnoflag)
    sprintf(buf + strlen(buf), ": %s", strerror(errno_save));
  strcat(buf, "\n");

  fflush(stdout); // in case stdout and stderr are the same
  fputs(buf, stderr);
  fflush(stderr); // sunos 4.1 doesn't grok NULL argument
  return;
}
#endif
