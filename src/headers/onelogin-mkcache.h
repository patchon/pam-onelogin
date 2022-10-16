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

#ifndef FUNCTIONS_DAEMON_INCLUDED
#define FUNCTIONS_DAEMON_INCLUDED
#include <curl/curl.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdio.h>

#include "curler.h"

#define AUTOMATIC_GROUP_ADD_GID 999999

int open_cache_files(FILE **file_passwd, FILE **file_grou, char *mode_passwd,
                     char *mode_group);

void add_users_and_primary_group(CURL *ch, struct curl_buffer *curl_buffer,
                                 char *bearer, char *users, FILE *file_passwd,
                                 FILE *file_group);

int fetch_pw_entry(char *uid, char *username, FILE *file_passwd, int len);
int fetch_grp_entry(int *gid);

void build_users_lists(CURL *ch, struct curl_buffer *curl_buffer, char *bearer,
                       char (*role_names)[512], char (*role_members)[512],
                       char (*role_ids)[512], char *users);

#endif
