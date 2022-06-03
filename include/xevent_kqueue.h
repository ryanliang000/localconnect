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

#ifndef _X_EVENT_KQUE_
#define _X_EVENT_KQUE_

#if defined(__APPLE__)
#include <sys/event.h>
int xfilter2filter(int xfilter) {
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
xevent_filter filter2xfilter(int kfilter) {
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
  EV_SET(&kevt, fd, xfilter2filter(xfilter), flag, 0, 0, NULL);
  return kevt;
}
// get proc func from fd and filter
xevent_callback geteventcallback(int fd, int kfilter) {
  xevent &evt = xeventpool()[fd];
  if (evt.fd != fd)
    return NULL;
  xevent_filter xflt = filter2xfilter(kfilter);
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
  return func(kevt.ident, filter2xfilter(kevt.filter));
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

const char *evfiltdesc(int flag) { return xfilterdesc(filter2xfilter(flag)); }

#endif // end #define __APPLE__
#endif // end #define _X_EVENT_KQUE_
