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

#include "headers/onelogin-mkcache.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "headers/config.h"
#include "headers/logging.h"
#include "headers/onelogin.h"

int main(int argc, char *argv[]) {
  (void) argv;
  char bearer[LENGTH_BEARER] = {'\0'};
  CURL *ch;
  FILE *file_passwd;
  FILE *file_group;

  if (argc >= 2) {
    printf(" ");
    printf(
        "\n This binary doesn't take any arguments, and won't print "
        "anything\n");
    printf(" unless you tell it to do so via its configuration file '%s'.\n\n",
           CONFIG_FNAME);
    printf(" You can choose among 'debug' and 'trace', where both options \n");
    printf(
        " should provide more than enough information about whats going "
        "on.\n\n");
    exit(0);
  }

  // Clear and open cache files
  if (!onelogin_cache_open(&file_passwd, CACHE_FILE_PASSWD, "w+") ||
      !onelogin_cache_open(&file_group, CACHE_FILE_GROUP, "w+")) {
    perr("error when opening cache file");
    exit(1);
  }

  // Open config, will exit on failure
  config_parse_file(CONFIG_FNAME);

  // Just a quick check
  if (strcmp(config.onelogin_user_roles.value, "") == 0) {
    perr("configuration is missing roles to lookup");
    exit(1);
  }

  // Create pointer to curl buffer for returned data and allocate memory
  struct curl_buffer *curl_buffer =
      (struct curl_buffer *)malloc(sizeof(struct curl_buffer));

  // Init curl, hardcode 10 second timeout for now
  if ((ch = curl_easy_init()) == NULL) {
    perr("could not initialize curl");
    goto cleanup;
  }
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, CURL_TIMEOUT);

  // Get onelogin authentication bearer
  if (!onelogin_get_auth_bearer(ch, curl_buffer, bearer, 0)) {
    perr("no authentication bearer for onelogin available");
    goto cleanup;
  }

  // Set the timeout again since the curl handle was reset
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, CURL_TIMEOUT);

  char users[4096] = {'\0'};
  char role_names[512][512] = {{'\0'}};
  char role_members[512][512] = {{'\0'}};
  char role_ids[512][512] = {{'\0'}};

  // Build comma separated list of users to lookup
  build_users_lists(ch, curl_buffer, bearer, role_names, role_members, role_ids,
                    users);

  if (strcmp(users, "") == 0) {
    pwrn("no user found in onelogin with required roles");
    goto cleanup;
  }

  // Based on the above list, get users info and add passwd and primary grp
  add_users_and_primary_group(ch, curl_buffer, bearer, users, file_passwd,
                              file_group);

  // Close files
  if (!onelogin_cache_close(&file_passwd) ||
      !onelogin_cache_close(&file_group)) {
    perr("failed to close filehandle for cache files");
    goto cleanup;
  }

  // Open cache files in read only and appending mode
  if (!onelogin_cache_open(&file_passwd, CACHE_FILE_PASSWD, "r") ||
      !onelogin_cache_open(&file_group, CACHE_FILE_GROUP, "a+")) {
    perr("error when opening cache file");
    goto cleanup;
  }

  // Second step is to add users to each role, which is based on the
  // roles they have in onelogin (not all the roles a user has, but from the
  // list of we have said in our config that they must have).
  char username[64];
  int len;
  char role_members_real[3200] = {'\0'};
  char *grp_members[64] = {'\0'};
  char **ptr_grp_members = &grp_members[0];
  char grp_members_buffer[64][256];
  char *p_user_to_add;
  char *strtok_user_to_add;
  struct group gr;
  int gid;
  int cnt;
  len = sizeof(username);

  // For each role name we have,
  for (unsigned int i = 0; i < sizeof(role_names) / 512; i++) {
    // Skip empty items
    if (strlen(role_members[i]) == 0 && strlen(role_names[i]) == 0) {
      continue;
    }

    // Skip if role has no members
    if (strlen(role_members[i]) == 0) {
      ptrc("role '%s' has no members", role_names[i]);
      continue;
    }

    ptrc("roleid = '%s', rolename = '%s', rolemembers = '%s'", role_ids[i],
         role_names[i], role_members[i]);

    // Parse comma separated user string and fetch username to build up
    // group member string,
    role_members_real[0] = '\0';
    username[0] = '\0';
    p_user_to_add = strtok_r(role_members[i], ",", &strtok_user_to_add);

    cnt = 0;
    while (p_user_to_add != NULL) {
      ptrc("will add user with uid '%s' to group '%s'", p_user_to_add,
           role_names[i]);

      if (!fetch_pw_entry(p_user_to_add, username, file_passwd, len)) {
        pwrn("could not find username for uid '%s',", p_user_to_add);
      }
      strcat(role_members_real, username);
      strcat(role_members_real, ",");

      // Copy member to temporary buffer
      strcpy(grp_members_buffer[cnt], username);

      // Assign pointer to username in temporary buffer
      grp_members[cnt] = grp_members_buffer[cnt];

      p_user_to_add = strtok_r(NULL, ",", &strtok_user_to_add);
      cnt++;
    }

    // Remove dangling comma,
    role_members_real[strlen(role_members_real) - 1] = '\0';

    // Create group struct,
    gr.gr_name = role_names[i];
    gr.gr_gid = util_strtoul(role_ids[i]);
    gr.gr_passwd = "x";
    gr.gr_mem = ptr_grp_members;

    errno = 0;
    if (putgrent(&gr, file_group) < 0) {
      perr("failure writing group entry to cache file '%s' (%s)",
           CACHE_FILE_PASSWD, strerror(errno));
      exit(1);
    }
  }

  if (strcmp(config.auto_add_group_to_user.value, "") != 0) {
    if (fetch_grp_entry(&gid)) {
      gr.gr_name = config.auto_add_group_to_user.value;
      gr.gr_gid = gid;
      gr.gr_passwd = "x";
      gr.gr_mem = ptr_grp_members;

      errno = 0;
      if (putgrent(&gr, file_group) < 0) {
        perr("failure writing group entry to cache file '%s' (%s)",
             CACHE_FILE_PASSWD, strerror(errno));
        exit(1);
      }
    }
  }

  // Close files
  if (!onelogin_cache_close(&file_passwd) ||
      !onelogin_cache_close(&file_group)) {
    perr("failed to close filehandle for cache files");
    exit(1);
  }

cleanup:
  free(curl_buffer);
  curl_easy_cleanup(ch);
  curl_easy_reset(ch);
}

void build_users_lists(CURL *ch, struct curl_buffer *curl_buffer, char *bearer,
                       char (*role_names)[512], char (*role_members)[512],
                       char (*role_ids)[512], char *users) {
  char *p_role_to_lookup;

  pinf("building list of users that has any of the roles '%s'",
       config.onelogin_user_roles.value);

  // Parse comma separated string of roles, and query users onelogin for users
  // that has the specified role
  p_role_to_lookup = strtok(config.onelogin_user_roles.value, ",");
  int cnt = 0;
  while (p_role_to_lookup != NULL) {
    // Put rolenames in a 2d-array with the same index as
    // role_members-2d-array. Doing so we can map users to a group.
    strncpy(role_names[cnt], p_role_to_lookup, 511);

    if (!onelogin_get_users_with_role(ch, curl_buffer, bearer, p_role_to_lookup,
                                      role_members, role_ids, users, cnt)) {
      pwrn("an error occured / no users with role '%s' returned from onelogin",
           p_role_to_lookup);
    }
    p_role_to_lookup = strtok(NULL, ",");
    cnt++;
  }

  // Remove dangling comma
  users[strlen(users) - 1] = '\0';
  pinf("users that has any of the required roles '%s'", users);
}

void add_users_and_primary_group(CURL *ch, struct curl_buffer *curl_buffer,
                                 char *bearer, char *users, FILE *file_passwd,
                                 FILE *file_group) {
  char *p_user_to_lookup;
  char *strtok_user_to_lookup;
  char key_to_extract[256];
  char extracted_onelogin_username[256];
  char extracted_onelogin_email[256];
  char home_dir[512];
  char user_data[32768];
  struct passwd pw;
  struct group gr;

  // Parse comma separated string and get information about each user
  p_user_to_lookup = strtok_r(users, ",", &strtok_user_to_lookup);
  while (p_user_to_lookup != NULL) {
    pinf("will lookup user %s", p_user_to_lookup);

    if (!onelogin_get_user(ch, curl_buffer, bearer, p_user_to_lookup,
                           user_data)) {
      // This should not happen, we got an id from a role, but when we lookup
      // that id, we got no info
      perr("no user with id '%s' returned from onelogin", p_user_to_lookup);
      exit(1);
    } else {
      // We got info about a user
      pinf("data from user lookup '%s'", user_data);

      // FIXME, just a quick check to see that we have something that looks
      // like a json
      if (user_data[strlen(user_data) - 1] != '}') {
        perr("allocated user data buffer is to small or no json returned");
        exit(1);
      }

      // Extract username from returned data
      sprintf(key_to_extract, "\"username\":\"");
      extract_value_from_key(user_data, key_to_extract, "\"",
                             extracted_onelogin_username);

      // Make sure our delimiter is in place
      if (strstr(extracted_onelogin_username, "@") == 0) {
        perr("could not find the '@' delimiter in username");
        exit(1);
      }

      strtok(extracted_onelogin_username, "@");
      pinf("extracted '%s' as username", extracted_onelogin_username);

      // Extract email
      sprintf(key_to_extract, "\"email\":\"");
      extract_value_from_key(user_data, key_to_extract, "\"",
                             extracted_onelogin_email);

      pinf("extracted '%s' as email", extracted_onelogin_email);

      // Create pw struct, hardcode homedir and shell for now
      snprintf(home_dir, 262, "/home/%s", extracted_onelogin_username);
      pw.pw_gecos = extracted_onelogin_email;
      pw.pw_name = extracted_onelogin_username;
      pw.pw_uid = util_strtoul(p_user_to_lookup);
      pw.pw_gid = util_strtoul(p_user_to_lookup);
      pw.pw_dir = home_dir;
      pw.pw_shell = "/bin/bash";

      pinf("created pwentry for '%s', %s:x:%i:%i:%s:%s:%s",
           extracted_onelogin_username, pw.pw_name, pw.pw_uid, pw.pw_gid,
           pw.pw_dir, pw.pw_gecos, pw.pw_shell);

      errno = 0;
      if (putpwent(&pw, file_passwd) < 0) {
        util_print_pw_str("failed to store the following entry in cache", &pw);
        perr("failure writing entry to cache file '%s' (%s)", CACHE_FILE_PASSWD,
             strerror(errno));
        exit(1);
      }

      // Create group struct,
      gr.gr_name = extracted_onelogin_username;
      gr.gr_gid = util_strtoul(p_user_to_lookup);
      gr.gr_passwd = "x";

      errno = 0;
      if (putgrent(&gr, file_group) < 0) {
        perr("failure writing entry to cache file '%s' (%s)", CACHE_FILE_GROUP,
             strerror(errno));
        exit(1);
      }
      util_print_pw_str("successfully stored the following entry in cache",
                        &pw);
    }

    p_user_to_lookup = strtok_r(NULL, ",", &strtok_user_to_lookup);
  }
}

int fetch_pw_entry(char *uid, char *username, FILE *file_passwd, int len) {
  int i = 0;
  int x = 0;
  size_t buflen = 4096;
  char buf[buflen];
  struct passwd pw, *pwp;
  uid_t uid_to_fetch;

  ptrc("reading onelogin cached entries from '%s'", CACHE_FILE_PASSWD);

  uid_to_fetch = util_strtoul(uid);
  if ((int32_t)uid_to_fetch < 0) {
    perr(" !!!! HANDLE EXIT !!!! ");
    exit(1);
  }

  rewind(file_passwd);
  while (1) {
    // Get entries from our cache file
    i = fgetpwent_r(file_passwd, &pw, buf, buflen, &pwp);

    // Return on error/eof
    if (i) {
      pwrn("looped '%d' times", x);
      pwrn("fgetpwent_r returned '%i'", i);
      return 0;
    }

    // Look for match
    if (pwp->pw_uid == uid_to_fetch) {
      strncpy(username, pwp->pw_name, len - 1);
      pinf("found username '%s' for uid '%s'", pwp->pw_name, uid);
      return 1;
    }
    x++;
  }

  return 0;
}

int fetch_grp_entry(int *gid) {
  struct group grp;
  struct group *grpp;
  char buf[256];
  int x;

  setgrent();
  while (1) {
    x = getgrent_r(&grp, buf, sizeof(buf), &grpp);
    if (x) {
      pwrn("group '%s' could not be found, won't be able to add users to it",
           config.auto_add_group_to_user.value);
      break;
    }
    if (strcmp(grpp->gr_name, config.auto_add_group_to_user.value) == 0) {
      ptrc("found group '%s', will add users to it",
           config.auto_add_group_to_user.value);
      *gid = grpp->gr_gid;
      return 1;
    }
  }
  endgrent();
  return 0;
}
