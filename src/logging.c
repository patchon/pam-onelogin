/* * *
#
# (c) 2022-2022, Patrik Martinsson <patrik@redlin.se>
#
# This file is part of pam-onelogin
#
# pam-onelogin is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pam-onelogin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pam-onelogin.  If not, see <http://www.gnu.org/licenses/>.
*
* * */

#include "headers/logging.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "headers/config.h"

char* timestamp() {
  // Allocate memory for date str
  char* buf = malloc(32);

  // Construct date
  time_t timer;
  struct tm* tm_info;
  timer = time(NULL);
  tm_info = localtime(&timer);

  // Format and copy date into our allocated buffer
  strftime(buf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

  return buf;
}

static void _log(const char *prefix, const char *format, va_list args) {
  char* time = timestamp();
  char logstr[2048];
  int len = snprintf(logstr, sizeof(logstr), "[ %s ] [ %s ] ", prefix, time);
  free(time);
  vsnprintf(&logstr[len], sizeof(logstr) - len, format, args);

  // Errors and warning always prints
  if (strcmp(prefix, "err") == 0 ||
      strcmp(prefix, "wrn") == 0){
    fprintf(stderr, "%s\n", logstr);
    openlog("pam-onelogin", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", logstr);
  }else{
    // Other messages prints if enabled
    if (config.log_stdout.value == 1)
      fprintf(stdout, "%s\n", logstr);

    if (config.log_syslog.value == 1) {
      openlog("pam-onelogin", LOG_PID, LOG_USER);
      syslog(LOG_INFO, "%s", logstr);
    }
  }
}

void pinf(char* str, ...) {
  if (config.debug.value == 0) {
    return;
  }

  va_list args;
  va_start(args, str);
  _log("inf", str, args);
  va_end(args);
}

void ptrc(char* str, ...) {
  if (config.trace.value == 0) {
    return;
  }

  va_list args;
  va_start(args, str);
  _log("trc", str, args);
  va_end(args);
}

void pwrn(char* str, ...) {
  va_list args;
  va_start(args, str);
  _log("wrn", str, args);
  va_end(args);
}

void perr(char* str, ...) {
  va_list args;
  va_start(args, str);
  _log("err", str, args);
  va_end(args);
}

void pfnc(const char* str) {
  ptrc("");
  ptrc(
      "/ / / / / / / / / / / * * * * * * * * \\ \\ \\ \\ \\ \\ \\ \\ \\ \\ "
      "\\ ");
  ptrc("");
  ptrc(" -> %s is getting called ", str);
  ptrc("");
  ptrc(
      "\\ \\ \\ \\ \\ \\ \\ \\ \\ \\ \\ * * * * * * * * / / / / / / / / / / "
      "/ ");
  ptrc("");
}
