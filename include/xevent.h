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
int xfilter2filter(int xfilter);
xevent_filter filter2xfilter(int kfilter);
// valid reg number
int xeventnum(){return _fdnums;}

#if defined(__APPLE__)
  #include "xevent_kqueue.h"
#elif defined(__linux__) || defined(__unix__) || defined(_POSIX_VERSION)
  #include "xevent_epoll.h"
#else
  #include "xevent_select.h"
#endif // end

#endif // end #define __X_EVENT__
