
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

#ifndef FUNCTIONS_CURLER_INCLUDED
#define FUNCTIONS_CURLER_INCLUDED
#include <curl/curl.h>

#include "config.h"

// Struct for handling curl buffer data
struct curl_buffer {
  char *response;
  size_t size;
};

#define LENGTH_BEARER 256
#define LENGTH_HEADER_DATA 1024
#define LENGTH_URL 256
#define CURL_TIMEOUT 10

CURLcode curl_call(CURL *ch, struct curl_buffer *curl_buffer, const char *url);
size_t curl_callback(void *data, size_t size, size_t nmemb, void *userp);
int extract_value_from_key(char *str, char *key, const char *end_delim,
                           char *val);

#endif
