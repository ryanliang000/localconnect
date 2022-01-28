/*
 * xevent backend
 *
 * Copyright (c) 2020 Rain Liang
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifica-
 * tion, are permitted provided that the following conditions are met:
 *
 *   1.  Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *   2.  Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MER-
 * CHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPE-
 * CIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTH-
 * ERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * the GNU General Public License ("GPL") version 2 or any later version,
 * in which case the provisions of the GPL are applicable instead of
 * the above. If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use your
 * version of this file under the BSD license, indicate your decision
 * by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL. If you do not delete the
 * provisions above, a recipient may use your version of this file under
 * either the BSD or the GPL.
 */

#ifndef _X_EVENT_
#define _X_EVENT_

#include "log.h"
#include <errno.h>

#define MAX_EVENT_POOL 2048
#define MAX_EVENT_RECV 128
int _fdnums = 0;
int _epfd = 0;
enum xevent_filter {
  xfilter_read = 0,
  xfilter_write = 1,
  xfilter_error = 2,
  xfilter_count = 3
};
enum xevent_action { xaction_add = 0, xaction_del = 1, xaction_count = 2 };
typedef int (*xevent_callback)(int fd, int filter);
struct xevent_func {
  int filter;
  xevent_callback func;
  xevent_func() : filter(-1), func(NULL) {}
  void reset() {
    filter = -1;
    func = NULL;
  }
};
struct xevent {
  int fd;
  xevent_func funcs[xfilter_count];
  xevent() : fd(-1) {}
  xevent(int infd) : fd(infd) {}
  bool valid() {
    if (fd == -1)
      return false;
    for (int i = 0; i < xfilter_count; i++) {
      if (funcs[i].filter != -1)
        return true;
    }
    return false;
  }
  char* desc(){
    static char _desc[64] = {0};
    sprintf(_desc, "fd=%d, filters:", fd);
    for (int i=0; i<xfilter_count; i++)
      sprintf(_desc + strlen(_desc), "%d ", funcs[i].filter);
    return _desc;  
  }
};
struct xevent _xeventpool[MAX_EVENT_POOL];
xevent *xeventpool() { return _xeventpool; }
const char *xfilterdesc(int xfilter) {
  static char _desc[64];
  switch (xfilter) {
  case xfilter_read:
    return "READ";
  case xfilter_write:
    return "WRITE";
  case xfilter_error:
    return "ERROR";
  default:
    sprintf(_desc, "flt-%d", xfilter);
  }
  return _desc;
}
// init xevent data
int initxevent();
// reg event callback func
int regxevent(int fd, xevent_filter xfilter, xevent_callback func);
// unreg event callback
int unregxevent(int fd, xevent_filter xfilter);
int unregxevent(int fd);
// dispatch event once
int dispatchxevent(int timeoutsecond);
// filter map
int xfilter2kfilter(int xfilter);
xevent_filter kfilter2xfilter(int kfilter);
#if defined(__APPLE__)
#include <sys/event.h>
int xfilter2kfilter(int xfilter) {
  switch (xfilter) {
  case xfilter_read:
    return EVFILT_READ;
  case xfilter_write:
    return EVFILT_WRITE;
  case xfilter_error:
    return EVFILT_EXCEPT;
  default:;
  }
  return EVFILT_EXCEPT;
}
xevent_filter kfilter2xfilter(int kfilter) {
  switch (kfilter) {
  case EVFILT_READ:
    return xfilter_read;
  case EVFILT_WRITE:
    return xfilter_write;
  case EVFILT_EXCEPT:
    return xfilter_error;
  default:;
  }
  return xfilter_error;
}
// build kevent from info
struct kevent buildkevent(int fd, int xfilter, xevent_action act) {
  int flag = EV_ADD | EV_ENABLE;
  if (act == xaction_del)
    flag = EV_DELETE;
  struct kevent kevt;
  EV_SET(&kevt, fd, xfilter2kfilter(xfilter), flag, 0, 0, NULL);
  return kevt;
}
// get proc func from fd and filter
xevent_callback geteventcallback(int fd, int kfilter) {
  xevent &evt = xeventpool()[fd];
  if (evt.fd != fd)
    return NULL;
  xevent_filter xflt = kfilter2xfilter(kfilter);
  if (evt.funcs[xflt].filter == -1)
    return NULL;
  return evt.funcs[xflt].func;
}
xevent_callback geteventcallback(struct kevent &kevt) {
  return geteventcallback(kevt.ident, kevt.filter);
}
int initxevent() {
  _epfd = kqueue();
  if (_epfd == -1) {
    LOG_E("init xevent with kqueue error");
    return -1;
  }
  return 0;
}
const char *xfilterdesc(int xfilter);
// 0-Succ, -1-failed
int regxevent(int fd, xevent_filter filter, xevent_callback func) {
  if (fd >= MAX_EVENT_POOL) {
    LOG_E("fd exceed max event pool size(%d >= %d)", fd, MAX_EVENT_POOL);
    return -1;
  }
  xevent &evt = xeventpool()[fd];
  // only update func
  if (evt.funcs[filter].filter != -1) {
    evt.funcs[filter].func = func;
    return 0;
  }
  // modify data
  evt.fd = fd;
  evt.funcs[filter].filter = filter;
  evt.funcs[filter].func = func;
  // add event
  struct kevent kevt = buildkevent(fd, filter, xaction_add);
  kevent(_epfd, &kevt, 1, NULL, 0, NULL);
  LOG_D("regevent: fd-%d, filter-%s", fd, xfilterdesc(filter));
  _fdnums++;
  return 0;
};
int unregxevent(int fd, xevent_filter filter) {
  xevent &evt = xeventpool()[fd];
  if (evt.fd == -1 || evt.funcs[filter].filter == -1) {
    LOG_D("remove fd-filter(%d-%d) event not exist", fd, filter);
    return 0;
  }
  // remove data
  evt.funcs[filter].reset();
  // remove event
  struct kevent kevt = buildkevent(fd, filter, xaction_del);
  kevent(_epfd, &kevt, 1, NULL, 0, NULL);
  _fdnums--;
  LOG_D("unregevent: fd-%d, filter-%s, left-%d", fd, xfilterdesc(filter), _fdnums);
  return 0;
};
int unregxevent(int fd) {
  xevent &evt = xeventpool()[fd];
  if (evt.fd == -1) {
    LOG_D("remove fd(%d) event not exist", fd);
    return 0;
  }
  struct kevent kevts[xfilter_count];
  int nums = 0;
  // modify data
  for (int i = 0; i < xfilter_count; i++) {
    if (evt.funcs[i].filter != -1) {
      kevts[nums] = buildkevent(fd, evt.funcs[i].filter, xaction_del);
      evt.funcs[i].reset();
      nums++;
    }
  }
  evt.fd = -1;
  // remove event
  kevent(_epfd, kevts, nums, NULL, 0, NULL);
  _fdnums -= nums;
  LOG_R("unregevent-fd: fd-%d, nums-%d, left-%d", fd, nums, _fdnums);
  return 0;
}
int call_event_func(struct kevent &kevt) {
  xevent_callback func = geteventcallback(kevt);
  if (func == NULL) {
    LOG_D("call_event_func return NULL, fd=%d", int(kevt.ident));
    return -1;
  }
  return func(kevt.ident, kevt.filter);
}
struct kevent _events[MAX_EVENT_RECV];
struct timespec _tvs;
// 0-succ, -1-failed
int dispatchxevent(int timeoutsecond) {
  _tvs.tv_sec = timeoutsecond;
  _tvs.tv_nsec = 0;
  int nfds = kevent(_epfd, NULL, 0, _events, MAX_EVENT_RECV, &_tvs);
  if (nfds < 0) {
    LOG_E("epoll wait error[%d], ignored!", errno);
    return -1;
  }
  for (int i = 0; i < nfds; i++) {
    call_event_func(_events[i]);
  }
  return 0;
};

const char *evfiltdesc(int flag) { return xfilterdesc(kfilter2xfilter(flag)); }

#elif defined(__linux__) || defined(__unix__) || defined(_POSIX_VERSION)
#include <sys/epoll.h>
int xfilter2kfilter(int xfilter) {
  switch (xfilter) {
  case xfilter_read:
    return EPOLLIN;
  case xfilter_write:
    return EPOLLOUT;
  case xfilter_error:
    return EPOLLERR;
  default:;
  }
  return EPOLLERR;
}
xevent_filter kfilter2xfilter(int kfilter) {
  switch (kfilter) {
  case EPOLLIN:
    return xfilter_read;
  case EPOLLOUT:
    return xfilter_write;
  case EPOLLERR:
    return xfilter_error;
  default:;
  }
  return xfilter_error;
}
// build epoll event
struct epoll_event buildkevent(xevent &evt) {
  struct epoll_event epollevt;
  epollevt.data.fd = evt.fd;
  epollevt.events = 0;
  if (evt.fd == -1)
    return epollevt;
  for (int i = 0; i < xfilter_count; i++) {
    if (evt.funcs[i].filter != -1) {
      epollevt.events |= xfilter2kfilter(evt.funcs[i].filter);
    }
  }
  return epollevt;
}
int initxevent() {
  _epfd = epoll_create(MAX_EVENT_POOL);
  if (_epfd == -1) {
    LOG_E("init xevent with epoll error");
    return -1;
  }
  return 0;
}

// 0-Succ, -1-failed
int regxevent(int fd, xevent_filter filter, xevent_callback func) {
  if (fd >= MAX_EVENT_POOL) {
    LOG_E("fd exceed max event pool size(%d >= %d)", fd, MAX_EVENT_POOL);
    return -1;
  }
  xevent &evt = xeventpool()[fd];
  // only update func
  if (evt.funcs[filter].filter != -1) {
    evt.funcs[filter].func = func;
    return 0;
  }
  // modify data
  bool valid = evt.valid();
  evt.fd = fd;
  evt.funcs[filter].filter = filter;
  evt.funcs[filter].func = func;
  // add event
  struct epoll_event epollevt = buildkevent(evt);
  if (valid)
    epoll_ctl(_epfd, EPOLL_CTL_MOD, fd, &epollevt);
  else
    epoll_ctl(_epfd, EPOLL_CTL_ADD, fd, &epollevt);
  LOG_D("regevent: fd-%d, filter-%s", fd, xfilterdesc(filter));
  _fdnums++;
  return 0;
};
int unregxevent(int fd, xevent_filter filter) {
  xevent &evt = xeventpool()[fd];
  if (evt.fd == -1 || evt.funcs[filter].filter == -1) {
    LOG_D("remove fd-filter(%d-%d) event not exist", fd, filter);
    return 0;
  }
  // remove data
  evt.funcs[filter].reset();
  // remove event
  bool valid = evt.valid();
  struct epoll_event epollevt = buildkevent(evt);
  if (valid) {
    epoll_ctl(_epfd, EPOLL_CTL_MOD, fd, &epollevt);
  } else {
    epoll_ctl(_epfd, EPOLL_CTL_DEL, fd, &epollevt);
  }
  _fdnums--;
  LOG_D("unregevent: fd-%d, filter-%s, left-%d", fd, xfilterdesc(filter), _fdnums);
  return 0;
};
int unregxevent(int fd) {
  xevent &evt = xeventpool()[fd];
  if (evt.fd == -1) {
    LOG_D("remove fd(%d) event not exist", fd);
    return 0;
  }
  int nums = 0;
  // modify data
  for (int i = 0; i < xfilter_count; i++) {
    if (evt.funcs[i].filter != -1) {
      evt.funcs[i].reset();
      nums++;
    }
  }
  evt.fd = -1;
  // remove event
  struct epoll_event epollevt = buildkevent(evt);
  epoll_ctl(_epfd, EPOLL_CTL_DEL, fd, &epollevt);
  _fdnums -= nums;
  LOG_R("unregevent-fd: fd-%d, nums-%d, left-%d", fd, nums, _fdnums);
  return 0;
}
int call_event_func(struct epoll_event &evt) {
  int fd = evt.data.fd;
  if (fd == -1)
    return -1;
  xevent &xevt = xeventpool()[fd];
  if (fd != xevt.fd)
    return -1;
  for (int i = 0; i < xfilter_count; i++) {
    if (xevt.funcs[i].filter == -1)
      continue;
    int kfilter = xfilter2kfilter(xevt.funcs[i].filter);
    if (kfilter & evt.events) {
      if (xevt.funcs[i].func == NULL)
        continue;
      int rt = xevt.funcs[i].func(fd, xevt.funcs[i].filter);
      if (rt < 0)
        return rt;
    }
  }
  return 0;
}
struct epoll_event _events[MAX_EVENT_RECV];
// 0-succ, -1-failed
int dispatchxevent(int timeoutsecond) {
  int nfds = epoll_wait(_epfd, _events, MAX_EVENT_RECV, timeoutsecond * 1000);
  if (nfds < 0) {
    LOG_E("epoll wait error[%d], ignored!", errno);
    return -1;
  }
  for (int i = 0; i < nfds; i++) {
    call_event_func(_events[i]);
  }
  return 0;
};

#endif // end of #if defined(__linux__)
#endif // end #define __X_EVENT__
