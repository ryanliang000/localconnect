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
#ifndef _LOG_H_202111_
#define _LOG_H_202111_
#include <stdio.h>
#include <string.h>

#ifndef _LOG_BASE_FUNC
#define _LOG_BASE_FUNC
#include <time.h>
static char* __gettime(){
   static char buf[32] = {0};
   time_t t = time(NULL);
   struct tm* local = localtime(&t);
   sprintf(buf, "%04d%02d%02d-%02d:%02d:%02d",
        local->tm_year + 1900, local->tm_mon + 1, local->tm_mday,
        local->tm_hour, local->tm_min, local->tm_sec);
   return buf;
}
#define _LOG(fd, title, ...)                                                    \
  fprintf(fd, "%s ", __gettime());                                              \
  fprintf(fd, title);                                                          \
  fprintf(fd, __VA_ARGS__);                                                    \
  fprintf(fd, " (%s:%d)\n", __FILE__, __LINE__);
#endif

#ifdef REL
#define LOG_E(...) _LOG(stderr, "[ERR]", __VA_ARGS__)
#define LOG_W(...) 
#define LOG_R(...)
#define LOG_I(...)
#elif defined RUN
#define LOG_E(...) _LOG(stderr, "[ERR]", __VA_ARGS__)
#define LOG_R(...) _LOG(stdout, "[RUN]", __VA_ARGS__)
#define LOG_W(...) _LOG(stdout, "[WARN]", __VA_ARGS__)
#define LOG_I(...)
#else
#define LOG_E(...) _LOG(stderr, "[ERR]", __VA_ARGS__)
#define LOG_W(...) _LOG(stdout, "[WARN]", __VA_ARGS__)
#define LOG_R(...) _LOG(stdout, "[RUN]", __VA_ARGS__)
#define LOG_I(...) _LOG(stdout, "[INF]", __VA_ARGS__)
#endif

#define LOG(...) _LOG(stdout, "", __VA_ARGS__) 

#ifdef DBG
#define LOG_D(...) _LOG(stdout, "[DBG]", __VA_ARGS__)
#else
#define LOG_D(...)
#endif

#endif
