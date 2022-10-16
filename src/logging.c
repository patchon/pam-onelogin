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
#include <stdio.h>
#include <stdlib.h>
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

int calculate_buf_length(char* str, va_list argp_copy) {
  int length;
  char buf[2];

  // String will never fit buffer, so vsnprintf will always return the length
  // that we need - the null terminator
  length = vsnprintf(buf, sizeof(buf), str, argp_copy);

  // Not sure if this can happen
  if (length < 0) {
    fprintf(stderr, "error calculating length for log msg, '%s'", str);
    exit(1);
  }

  return length + 1U;
}

void pinf(char* str, ...) {
  if (config.debug.value == 0) {
    return;
  }

  if (config.log_syslog.value == 1) {
    openlog("Logs", LOG_PID, LOG_USER);
  }

  int ret;

  // Enable use of passing formatted strings directly
  va_list argp;
  va_start(argp, str);

  // Make a copy since we need it more than once, im sure there are better ways
  // for this
  va_list argp_copy;
  va_copy(argp_copy, argp);
  va_list argp_copy_;
  va_copy(argp_copy_, argp);

  if (config.log_stdout.value == 1) {
    char* time = timestamp();
    fprintf(stdout, "[ inf ] [ %s ] ", time);
    vfprintf(stdout, str, argp);
    fprintf(stdout, "\n");
    va_end(argp);
    free(time);
  }

  if (config.log_syslog.value == 1) {
    // Calculate the size we need for our buffer
    va_start(argp_copy, str);
    int length;
    length = calculate_buf_length(str, argp_copy);
    va_end(argp_copy);

    // Allocate buffer for syslog
    char* buf = malloc(sizeof(char) * length);
    if (buf == NULL) {
      fprintf(stderr, "can not allocate buffer for log msg\n");
      exit(1);
    }

    va_start(argp_copy_, str);

    ret = vsprintf(buf, str, argp_copy_);
    if (ret < 0) {
      fprintf(stderr, "failed to write log msg to buffer\n");
      exit(1);
    }
    va_end(argp_copy_);

    syslog(LOG_INFO, buf);
    free(buf);
  }
}

void ptrc(char* str, ...) {
  if (config.trace.value == 0) {
    return;
  }

  if (config.log_syslog.value == 1) {
    openlog("Logs", LOG_PID, LOG_USER);
  }

  int ret;

  // Enable use of passing formatted strings directly
  va_list argp;
  va_start(argp, str);

  // Make a copy since we need it more than once, im sure there are better ways
  // for this
  va_list argp_copy;
  va_copy(argp_copy, argp);
  va_list argp_copy_;
  va_copy(argp_copy_, argp);

  if (config.log_stdout.value == 1) {
    char* time = timestamp();
    fprintf(stdout, "[ trc ] [ %s ] ", time);
    vfprintf(stdout, str, argp);
    fprintf(stdout, "\n");
    va_end(argp);
    free(time);
  }

  if (config.log_syslog.value == 1) {
    // Calculate the size we need for our buffer
    va_start(argp_copy, str);
    int length;
    length = calculate_buf_length(str, argp_copy);
    va_end(argp_copy);

    // Allocate buffer for syslog
    char* buf = malloc(sizeof(char) * length);
    if (buf == NULL) {
      fprintf(stderr, "can not allocate buffer for log msg\n");
      exit(1);
    }

    va_start(argp_copy_, str);

    ret = vsprintf(buf, str, argp_copy_);
    if (ret < 0) {
      fprintf(stderr, "failed to write log msg to buffer\n");
      exit(1);
    }
    va_end(argp_copy_);

    syslog(LOG_INFO, buf);
    free(buf);
  }
}

void pwrn(char* str, ...) {
  openlog("Logs", LOG_PID, LOG_USER);

  int ret;

  // Enable use of passing formatted strings directly
  va_list argp;
  va_start(argp, str);

  // Make a copy since we need it more than once, im sure there are better ways
  // for this
  va_list argp_copy;
  va_copy(argp_copy, argp);
  va_list argp_copy_;
  va_copy(argp_copy_, argp);

  char* time = timestamp();
  fprintf(stdout, "[ wrn ] [ %s ] ", time);
  vfprintf(stdout, str, argp);
  fprintf(stdout, "\n");
  va_end(argp);
  free(time);
  // Calculate the size we need for our buffer
  va_start(argp_copy, str);
  int length;
  length = calculate_buf_length(str, argp_copy);
  va_end(argp_copy);

  // Allocate buffer for syslog
  char* buf = malloc(sizeof(char) * length);
  if (buf == NULL) {
    fprintf(stderr, "can not allocate buffer for log msg\n");
    exit(1);
  }

  va_start(argp_copy_, str);

  ret = vsprintf(buf, str, argp_copy_);
  if (ret < 0) {
    fprintf(stderr, "failed to write log msg to buffer\n");
    exit(1);
  }
  va_end(argp_copy_);

  syslog(LOG_INFO, buf);
  free(buf);
}

void perr(char* str, ...) {
  openlog("Logs", LOG_PID, LOG_USER);

  int ret;

  // Enable use of passing formatted strings directly
  va_list argp;
  va_start(argp, str);

  // Make a copy since we need it more than once, im sure there are better ways
  // for this
  va_list argp_copy;
  va_copy(argp_copy, argp);
  va_list argp_copy_;
  va_copy(argp_copy_, argp);

  char* time = timestamp();
  fprintf(stdout, "[ err ] [ %s ] ", time);
  vfprintf(stdout, str, argp);
  fprintf(stdout, "\n");
  va_end(argp);
  free(time);
  // Calculate the size we need for our buffer
  va_start(argp_copy, str);
  int length;
  length = calculate_buf_length(str, argp_copy);
  va_end(argp_copy);

  // Allocate buffer for syslog
  char* buf = malloc(sizeof(char) * length);
  if (buf == NULL) {
    fprintf(stderr, "can not allocate buffer for log msg\n");
    exit(1);
  }

  va_start(argp_copy_, str);

  ret = vsprintf(buf, str, argp_copy_);
  if (ret < 0) {
    fprintf(stderr, "failed to write log msg to buffer\n");
    exit(1);
  }
  va_end(argp_copy_);

  syslog(LOG_INFO, buf);
  free(buf);
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
