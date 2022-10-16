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

#include <curl/curl.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../headers/config.h"
#include "../headers/logging.h"
#include "../headers/onelogin.h"

// Can't be in a header fiel because ISO C forbids forward references to 'enum'
// types
enum nss_status _nss_onelogin_getpwuid_r(uid_t uid, struct passwd *pwd,
                                         char *buf, size_t buflen,
                                         struct passwd **result);

enum nss_status _nss_onelogin_getpwnam_r(const char *name, struct passwd *pwd,
                                         char *buf, size_t buflen,
                                         struct passwd **result);

enum nss_status _nss_onelogin_getgrnam_r(const char *name, struct group *grp,
                                         char *buf, size_t buflen,
                                         struct group **result);

enum nss_status _nss_onelogin_getgrgid_r(gid_t gid, struct group *grp,
                                         char *restrict buf, size_t buflen,
                                         struct group **result);

enum nss_status _nss_onelogin_initgroups_dyn(const char *user, gid_t gid,
                                             long int *start, long int *size,
                                             gid_t **groupsp, long int limit,
                                             int *errnop);

enum nss_status _nss_onelogin_initgroups_dyn(const char *user, gid_t gid,
                                             long int *start, long int *size,
                                             gid_t **groupsp, long int limit,
                                             int *errnop) {
  char gids_buf[512] = {'\0'};
  char *strtok = NULL;
  char *ptr_gid = NULL;
  gid_t gid_to_add;

  FILE *file_group;

  // Open config, will exit on failure
  if (config.parsed.value != 1) config_parse_file(CONFIG_FNAME);

  // Open cache file
  if (!onelogin_cache_open(&file_group, CACHE_FILE_GROUP, "r")) {
    perr("error when opening cache file");
    exit(1);
  }

  pfnc(__func__);

  if (!onelogin_fetch_gids_belonging_to_user_from_cache(user, gids_buf,
                                                        file_group)) {
    pinf("no gids found");
  } else {
    pinf("found the following gids '%s'", gids_buf);
    ptr_gid = strtok_r(gids_buf, ",", &strtok);
    while (ptr_gid != NULL) {
      // Not sure about this, it should probably be handled in some way.
      // Similar to this
      // https://github.com/Sectoid/libnss-sqlite/blob/master/groups.c#L303
      // if (*start == *size) {
      //   perr("not implemented yet, user has to many groups");
      //   return NSS_STATUS_TRYAGAIN;
      // }

      pinf("adding gid '%s' to user '%s'", ptr_gid, user);
      gid_to_add = util_strtoul(ptr_gid);
      if ((int32_t)gid_to_add < 0) {
        perr(" !!!! HANDLE EXIT !!!! ");
        return NSS_STATUS_TRYAGAIN;
      }

      (*groupsp)[*start] = gid_to_add;
      (*start)++;
      ptr_gid = strtok_r(NULL, ",", &strtok);
    }
  }

  // Get rid of compiler warnings, not sure if this has any effect though
  (void)gid;
  (void)size;
  (void)limit;
  (void)errnop;
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_onelogin_getgrnam_r(const char *name, struct group *grp,
                                         char *buf, size_t buflen,
                                         struct group **result) {
  FILE *file_group;
  int found = 0;
  pfnc(__func__);

  // Open config, will exit on failure
  if (config.parsed.value != 1) config_parse_file(CONFIG_FNAME);

  // Open cache file
  if (!onelogin_cache_open(&file_group, CACHE_FILE_GROUP, "r")) {
    perr("error when opening cache file");
    exit(1);
  }

  if (onelogin_fetch_group_from_cache(name, 0, grp, file_group)) {
    result = &grp;
    found = 1;
  };

  // Close files
  if (!onelogin_cache_close(&file_group)) {
    perr("failed to close filehandle for cache files");
    return NSS_STATUS_UNAVAIL;
  }

  // User found, return success
  if (found == 1) {
    pinf("group '%s' with gid '%d' is found", (*result)->gr_name,
         (*result)->gr_gid);
    ptrc("returning 'NSS_STATUS_SUCCESS'");
    return NSS_STATUS_SUCCESS;
  }

  // No user was found
  pinf("group with gid '%d' is not found", grp->gr_gid);
  ptrc("returning 'NSS_STATUS_NOTFOUND'");
  return NSS_STATUS_NOTFOUND;

  // Get rid of compiler warnings, not sure if this has any effect though
  (void)buf;
  (void)buflen;
}

enum nss_status _nss_onelogin_getgrgid_r(gid_t gid, struct group *grp,
                                         char *restrict buf, size_t buflen,
                                         struct group **result) {
  FILE *file_group;
  char thing_to_lookup[256];
  int found = 0;
  pfnc(__func__);

  // Open config, will exit on failure
  if (config.parsed.value != 1) config_parse_file(CONFIG_FNAME);

  // Open cache file
  if (!onelogin_cache_open(&file_group, CACHE_FILE_GROUP, "r")) {
    perr("error when opening cache file");
    exit(1);
  }

  snprintf(thing_to_lookup, sizeof(thing_to_lookup) - 1, "%d", gid);
  if (onelogin_fetch_group_from_cache(thing_to_lookup, 1, grp, file_group)) {
    result = &grp;
    found = 1;
  };

  // Close files
  if (!onelogin_cache_close(&file_group)) {
    perr("failed to close filehandle for cache files");
    return NSS_STATUS_UNAVAIL;
  }

  // User found, return success
  if (found == 1) {
    pinf("group '%s' with gid '%d' is found", (*result)->gr_name,
         (*result)->gr_gid);
    ptrc("returning 'NSS_STATUS_SUCCESS'");
    return NSS_STATUS_SUCCESS;
  }

  // No user was found
  pinf("group with gid '%d' is not found", grp->gr_gid);
  ptrc("returning 'NSS_STATUS_NOTFOUND'");
  return NSS_STATUS_NOTFOUND;

  // Get rid of compiler warnings, not sure if this has any effect though
  (void)buf;
  (void)buflen;
}

enum nss_status _nss_onelogin_getpwuid_r(uid_t uid, struct passwd *pwd,
                                         char *buf, size_t buflen,
                                         struct passwd **result) {
  FILE *file_passwd;
  char thing_to_lookup[256];
  int found = 0;
  pfnc(__func__);

  // Open config, will exit on failure
  if (config.parsed.value != 1) config_parse_file(CONFIG_FNAME);

  // Open cache file
  if (!onelogin_cache_open(&file_passwd, CACHE_FILE_PASSWD, "r")) {
    perr("error when opening cache file");
    exit(1);
  }

  snprintf(thing_to_lookup, sizeof(thing_to_lookup) - 1, "%d", uid);
  if (onelogin_fetch_user_from_cache(thing_to_lookup, 1, pwd, file_passwd)) {
    result = &pwd;
    found = 1;
  };

  // Close files
  if (!onelogin_cache_close(&file_passwd)) {
    perr("failed to close filehandle for cache files");
    return NSS_STATUS_UNAVAIL;
  }

  // User found, return success
  if (found == 1) {
    pinf("username '%s' with uid '%d' is found", (*result)->pw_name,
         (*result)->pw_uid);
    ptrc("returning 'NSS_STATUS_SUCCESS'");
    return NSS_STATUS_SUCCESS;
  }

  // No user was found
  pinf("user with uid '%d' is not found", pwd->pw_uid);
  ptrc("returning 'NSS_STATUS_NOTFOUND'");
  return NSS_STATUS_NOTFOUND;

  // Get rid of compiler warnings, not sure if this has any effect though
  (void)buf;
  (void)buflen;
}

// The getpwnam_r function for the libnss_onelogin module
enum nss_status _nss_onelogin_getpwnam_r(const char *name, struct passwd *pwd,
                                         char *buf, size_t buflen,
                                         struct passwd **result) {
  FILE *file_passwd;
  int found = 0;
  pfnc(__func__);

  // Open config, will exit on failure
  if (config.parsed.value != 1) config_parse_file(CONFIG_FNAME);

  // Open cache file
  if (!onelogin_cache_open(&file_passwd, CACHE_FILE_PASSWD, "r")) {
    perr("error when opening cache file");
    exit(1);
  }

  // snprintf(thing_to_lookup, sizeof(thing_to_lookup) - 1, "%d", uid);
  if (onelogin_fetch_user_from_cache(name, 0, pwd, file_passwd)) {
    result = &pwd;
    found = 1;
  };

  // Close files
  if (!onelogin_cache_close(&file_passwd)) {
    perr("failed to close filehandle for cache files");
    return NSS_STATUS_UNAVAIL;
  }

  // User found, return success
  if (found == 1) {
    pinf("username '%s' with uid '%d' is found", (*result)->pw_name,
         (*result)->pw_uid);
    ptrc("returning 'NSS_STATUS_SUCCESS'");
    return NSS_STATUS_SUCCESS;
  }

  // No user was found
  pinf("user with uid '%d' is not found", pwd->pw_uid);
  ptrc("returning 'NSS_STATUS_NOTFOUND'");
  return NSS_STATUS_NOTFOUND;

  // Get rid of compiler warnings, not sure if this has any effect though
  (void)buf;
  (void)buflen;
}
