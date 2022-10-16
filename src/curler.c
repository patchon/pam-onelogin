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

#define _GNU_SOURCE
#include "headers/curler.h"

#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "headers/config.h"
#include "headers/logging.h"
#include "headers/onelogin.h"

CURLcode curl_call(CURL *ch, struct curl_buffer *curl_buffer, const char *url) {
  CURLcode ret;

  // Initialize the response data
  curl_buffer->response = (char *)calloc(1, sizeof(curl_buffer->response));
  curl_buffer->size = 0;

  if (curl_buffer->response == NULL) {
    perr("failed to allocate memoery for curl buffer response");
    return CURLE_FAILED_INIT;
  }

  // Set up the url and the callback function
  curl_easy_setopt(ch, CURLOPT_URL, url);
  curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);
  curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *)curl_buffer);

  // Do the actual call
  pinf("doing request to '%s'", url);
  if ((ret = curl_easy_perform(ch)) != CURLE_OK) {
    pwrn("error in curl call to '%s' (%s)", url, curl_easy_strerror(ret));
  };

  return ret;
}

// Callback for curl when receiving data
size_t curl_callback(void *data, size_t size, size_t nmemb, void *userp) {
  ptrc("in curl callback");
  // Calculate buffersize
  size_t realsize = size * nmemb;
  struct curl_buffer *mem = (struct curl_buffer *)userp;

  // Expand buffer using a tmp pointer (ie. new memory)
  char *ptr = realloc(mem->response, mem->size + realsize + 1);
  if (ptr == NULL) {
    perr("out of memory");
    exit(1);
  }

  // Assign that pointer to the response, copy data into it and set new size
  mem->response = ptr;
  memcpy(&(mem->response[mem->size]), data, realsize);
  mem->size += realsize;
  mem->response[mem->size] = 0;

  return realsize;
}

int extract_value_from_key(char *str, char *key, const char *end_delim,
                           char *val) {
  // Always use tmp pointer for strtok so we can use strtok from caller
  // functions without modifiying the same str
  char *tmp = NULL;

  // Create a new str that starts at the first occurance of the key we are
  // looking for, ie. delete everything in str before key.
  char *pkey = strstr(str, key);

  // Allocate a tmp buffer to store temporary string
  char *buf = malloc(strlen(str));

  if (buf == NULL) {
    pwrn("could not allocate memory for onelogin authentication bearer");
  } else {
    if (pkey != NULL) {
      // Copy our newly created str into a new str, where the start is,
      // old str - length of key, ie. new str starts at the value for the key
      // we want to extract.
      strcpy(buf, &pkey[strlen(key)]);

      // Extract everything before end delimiter, which is equal to the keys
      // value. Always remove } since we could be the last entry in the json
      // response (ie. if we trying to get the id we have the delimiter as
      // comma, but, if it is returned last, it looks like
      // this ---> "status":1,"id":78949920}] <---- ).
      strtok_r(buf, end_delim, &tmp);
      strtok_r(buf, "}", &tmp);

      // Copy that extracted value into the destionation,
      strncpy(val, buf, 255);
      pinf("successfully extracted '%s' (%s) from '%s'", buf, key, str);
      free(buf);
      return 1;
    } else {
      pwrn("error getting value for key '%s' from data '%s'", key, str);
    }
  }

  // Free tmp buffer
  return 0;
  free(buf);
}
