/*
 * logfunction
 *
 * Copyright (c) 2020 Rain
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
#ifndef _LOG_FUNCTION_ELAPSED_H_
#define _LOG_FUNCTION_ELAPSED_H_
#include "log.h"
#include <chrono>
#include <string>
#include <time.h>
class Elapsed {
public:
  Elapsed(const std::string &desc, bool bRunning = true)
      : m_desc(desc), m_duration(std::chrono::nanoseconds::zero()) {
    if (bRunning)
      start_running();
  }
  ~Elapsed() {
    total_running();
    double msec = m_duration.count() / 1000000.0;
    LOG("used time<%s>: %.3f(ms)", m_desc.c_str(), msec);
  }
  void Start() { start_running(); }
  void Stop() {
    total_running();
    stop_running();
  }

private:
  void stop_running() { m_bRunning = false; }
  void start_running() {
    m_bRunning = true;
    m_start = std::chrono::system_clock::now();
  }
  void total_running() {
    if (m_bRunning) {
      std::chrono::system_clock::time_point end =
          std::chrono::system_clock::now();
      m_duration +=
          std::chrono::duration_cast<std::chrono::nanoseconds>(end - m_start);
      m_start = end;
    }
  }
  std::chrono::nanoseconds m_duration;
  std::chrono::system_clock::time_point m_start;
  std::string m_desc;
  bool m_bRunning;
};

#endif
