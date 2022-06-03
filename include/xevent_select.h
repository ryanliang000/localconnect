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

#ifndef _X_EVENT_SELECT_
#define _X_EVENT_SELECT_

#if defined(_WIN32) || defined(_WIN64)
  #ifndef FD_SETSIZE
  #define FD_SETSIZE MAX_EVENT_POOL
  #endif
  #include "winsock2.h"
#else
  #include <sys/select.h>
#endif

fd_set _readset;
fd_set _writeset;
fd_set _exceptset;
int _maxfd = 0;
int _minfd = 0;

int xfilter2filter(int xfilter) {
  return xfilter;
}
xevent_filter filter2xfilter(int kfilter) {
  return (xevent_filter)kfilter;
}

void removexevent(int fd, int filter){
  if (fd == -1 || filter == -1) 
    return;
  switch(filter){
    case xfilter_read:
      FD_CLR(fd, &_readset);
      break;
    case xfilter_write:
      FD_CLR(fd, &_writeset);
      break;
    case xfilter_error:
      FD_CLR(fd, &_exceptset);
      break;
  }
}
void addxevent(int fd, int filter){
  if (fd == -1 || filter == -1)
    return;
  switch(filter){
    case xfilter_read:
      FD_SET(fd, &_readset);
      break;
    case xfilter_write:
      FD_SET(fd, &_writeset);
      break;
    case xfilter_error:
      FD_SET(fd, &_exceptset);
      break;
  }
  _maxfd = _maxfd >= fd ? _maxfd : (fd + 1);
  _minfd = _minfd < fd ? _minfd : fd;
}
// apply event
void appyxevent(xevent &evt) {
  if (evt.fd == -1)
    return;
  for (int i = 0; i < xfilter_count; i++) {
    if (evt.funcs[i].filter != -1) {
      addxevent(evt.fd, evt.funcs[i].filter);
    }
  }
}

// check set
int initxevent() {
  FD_ZERO(&_readset);
  FD_ZERO(&_writeset);
  FD_ZERO(&_exceptset);
  return 0;
}

// 0-Succ, -1-failed
int regxevent(int fd, xevent_filter filter, xevent_callback func) {
  if (fd >= MAX_EVENT_POOL) {
    LOG_E("fd exceed max event pool size(%d >= %d)", fd, MAX_EVENT_POOL);
    return -1;
  }
  if (fd >= FD_SETSIZE) {
    LOG_E("fd exceed FD_SETSIZE size(%d >= %d)", fd, FD_SETSIZE);
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
  addxevent(fd, filter);
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
  removexevent(fd, filter);
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
      removexevent(fd, evt.funcs[i].filter);
      evt.funcs[i].reset();
      nums++;
    }
  }
  evt.fd = -1;
  _fdnums -= nums;
  LOG_R("unregevent-fd: fd-%d, nums-%d, left-%d", fd, nums, _fdnums);
  return 0;
}
int call_event_func(int fd, xevent_filter filter) {
  if (fd == -1)
    return -1;
  xevent &xevt = xeventpool()[fd];
  if (fd != xevt.fd)
    return -1;
  for (int i = 0; i < xfilter_count; i++) {
    if (xevt.funcs[i].filter == -1)
      continue;
    if (xevt.funcs[i].filter == filter) {
      if (xevt.funcs[i].func == NULL)
        continue;
      int rt = xevt.funcs[i].func(fd, xevt.funcs[i].filter);
      if (rt < 0)
        return rt;
    }
  }
  return 0;
}
void recalcmaxfd(){
  xevent* p = xeventpool();
  _maxfd = 0;
  int fd = -1;
  for (int i=0; i<MAX_EVENT_POOL; i++){
    fd = (p+i)->fd;
    if (fd != -1){
      _maxfd = (_maxfd >= fd) ? _maxfd : (fd+1);
      _minfd = _minfd < fd ? _minfd : fd;
    }
  }
  LOG_D("recalc minfd=%d, maxfd = %d", _minfd, _maxfd - 1);
}

// 0-succ, -1-failed
int dispatchxevent(int timeoutsecond) {
  struct timeval tm = {0};
  tm.tv_sec = timeoutsecond;
  fd_set readset = _readset;
  fd_set writeset = _writeset;
  fd_set exceptset = _exceptset;
  int nfds = select(_maxfd, &readset, &writeset, &exceptset, &tm);
  if (nfds <= 0){
    return 0;
  }
  static int recalc = 0;
  for (int i= _minfd; i<_maxfd; i++){
    if (FD_ISSET(i, &readset)){
      call_event_func(i, xfilter_read);
    }
    if (FD_ISSET(i, &writeset)){
      call_event_func(i, xfilter_write);
    }
    if (FD_ISSET(i, &exceptset)){
      call_event_func(i, xfilter_error);
    }
    if (recalc++ > 5000){
      recalc = 0;
      recalcmaxfd();
    }
  }
  return 0;
};

#endif // end #define _X_EVENT_SELECT_
