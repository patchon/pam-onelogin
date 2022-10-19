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

int calculate_buf_length(const char* str, va_list argp_copy) {
  int len;
  char buf[2];

  // String will never fit buffer, so vsnprintf will always return the length
  // that we need - the null terminator
  len = vsnprintf(buf, sizeof(buf), str, argp_copy);

  // Not sure if this can happen
  if (len < 0) {
    fprintf(stderr, "error calculating length for log msg, '%s'", str);
    exit(1);
  }

  // fprintf(stderr, "calculated length for log msg, '%s' to %d \n", str, len);
  return len + 1U;
}

static void _log(const char* prefix, const char* format, va_list args) {
  char* time = timestamp();

  // Make a copy since we need it more than once, im sure there are better ways
  // for this
  va_list argp_copy;
  va_copy(argp_copy, args);
  va_list argp_copy_;
  va_copy(argp_copy_, args);

  int len;
  int ret;

  // Calculate buffer length. The 33 is simply the length of the
  // '[ xxx ] [ xxxx-xx-xx xx:xx:xx ] '.
  len = calculate_buf_length(format, argp_copy) + 33;
  char* buf = malloc(sizeof(char) * len);
  if (buf == NULL) {
    fprintf(stderr, "can not allocate buffer for log msg\n");
    exit(1);
  }

  // Add loglvel and timestamp to buffer
  snprintf(buf, 33, "[ %s ] [ %s ] ", prefix, time);

  // Append logmsg to our buffer, after loglevel/timestamp.
  ret = vsnprintf(&buf[32], len-33, format, argp_copy_);
  if (ret < 0) {
    fprintf(stderr, "failed to write log msg to buffer\n");
    exit(1);
  }

  // Errors and warning always prints
  if (strcmp(prefix, "err") == 0 || strcmp(prefix, "wrn") == 0) {
    fprintf(stderr, "%s\n", buf);
    openlog("pam-onelogin", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", buf);
  } else {
    // Other messages prints if enabled
    if (config.log_stdout.value == 1) fprintf(stdout, "%s\n", buf);

    if (config.log_syslog.value == 1) {
      openlog("pam-onelogin", LOG_PID, LOG_USER);
      syslog(LOG_INFO, "%s", buf);
    }
  }
  free(buf);
  free(time);
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
