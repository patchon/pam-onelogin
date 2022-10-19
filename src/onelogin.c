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

#include "headers/onelogin.h"

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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "headers/logging.h"

int onelogin_cache_open(FILE **file_descriptor, char *file_to_open,
                        char *file_mode) {
  errno = 0;
  *file_descriptor = fopen(file_to_open, file_mode);
  if (file_descriptor == NULL) {
    pwrn("could not open file '%s' in mode '%s' (%s)", file_to_open, file_mode,
         strerror(errno));
    return 0;
  }

  ptrc("successfully opened cache file '%s' in mode '%s'", file_to_open,
       file_mode);
  return 1;
}

int onelogin_cache_close(FILE **file) {
  int fno;
  char proclink[256];
  char filename[256];
  ssize_t bytes;
  errno = 0;

  fno = fileno(*file);
  if (fno < 0) {
    pwrn("failed to get filedescriptor for cache filestream (%s)",
         strerror(errno));
    return 0;
  }

  snprintf(proclink, sizeof(proclink) - 1, "/proc/self/fd/%d", fno);
  bytes = readlink(proclink, filename, 255);
  if (bytes < 0) {
    pwrn("failed to readlink for cache filestrean (%s)", strerror(errno));
    return 0;
  }

  filename[bytes] = '\0';
  if (fclose(*file) == EOF) {
    pwrn("could not close filestream for file '%s' (%s)", filename,
         strerror(errno));
    return 0;
  }

  ptrc("successfully closed file '%s'", filename);
  return 1;
}

int onelogin_fetch_user_from_cache(const char *thing_to_lookup, int lookup_uid,
                                   struct passwd *p, FILE *file_passwd) {
  uid_t uid;
  int i = 0;
  int entries = 0;
  int found = 0;

  size_t buflen = 4096;
  char buf[buflen];
  struct passwd pw, *pwp;
  // uid_t uid_to_fetch;

  pfnc(__func__);

  // Determine what we are looking up
  if (lookup_uid) {
    uid = util_strtoul(thing_to_lookup);
    if ((int32_t)uid < 0) {
      perr(" !!!! HANDLE EXIT !!!! ");
      exit(1);
    }
    pinf("looking for user with uid '%d' in cache", uid);
  } else {
    pinf("looking for user '%s' by username in cache", thing_to_lookup);
  }

  // Make sure we read from the beginning,
  rewind(file_passwd);
  while (1) {
    // Get entries from our cache file
    i = fgetpwent_r(file_passwd, &pw, buf, buflen, &pwp);

    // Return on error/eof
    if (i) {
      ptrc("looped '%d' entries, fgetpwent_r returned %d", entries, i);
      break;
    }

    // Look for match
    if (lookup_uid) {
      if (pwp->pw_uid == uid) {
        found = 1;
        break;
      }
    } else {
      if (strcmp(pwp->pw_name, thing_to_lookup) == 0) {
        found = 1;
        break;
      }
    }
    entries++;
  }

  if (found == 1) {
    *p = *pwp;
    util_print_pw_str("successfully found the following entry in cache", p);
    return 1;
  }

  if (lookup_uid) {
    ptrc("could not find user by uid '%s' in cache", thing_to_lookup);
  } else {
    ptrc("could not find user by username '%s' in cache", thing_to_lookup);
  }

  return 0;
}

int onelogin_fetch_group_from_cache(const char *thing_to_lookup, int lookup_gid,
                                    struct group *g, FILE *file_group) {
  gid_t gid;
  int i = 0;
  int entries = 0;
  int found = 0;

  size_t buflen = 4096;
  char buf[buflen];
  struct group gr, *grp;
  ;

  pfnc(__func__);

  // Determine what we are looking up
  if (lookup_gid) {
    gid = util_strtoul(thing_to_lookup);
    if ((int32_t)gid < 0) {
      perr(" !!!! HANDLE EXIT !!!! ");
      exit(1);
    }
    pinf("looking for group with gid '%d' in cache", gid);
  } else {
    pinf("looking for group '%s' by group name in cache", thing_to_lookup);
  }

  // Make sure we read from the beginning,
  rewind(file_group);
  while (1) {
    // Get entries from our cache file
    i = fgetgrent_r(file_group, &gr, buf, buflen, &grp);

    // Return on error/eof
    if (i) {
      ptrc("looped '%d' entries, fgetgrent_r returned %d", entries, i);
      break;
    }

    // Look for match
    if (lookup_gid) {
      if (grp->gr_gid == gid) {
        found = 1;
        break;
      }
    } else {
      if (strcmp(grp->gr_name, thing_to_lookup) == 0) {
        found = 1;
        break;
      }
    }
    entries++;
  }

  if (found == 1) {
    *g = *grp;
    pinf("successfully found group '%s' with gid '%d' in cache", g->gr_name,
         g->gr_gid);
    return 1;
  }

  if (lookup_gid) {
    pwrn("could not find group by gid '%s' in cache", thing_to_lookup);
  } else {
    pwrn("could not find group by group name '%s' in cache", thing_to_lookup);
  }

  return 0;
}

int onelogin_fetch_gids_belonging_to_user_from_cache(const char *username,
                                                     char *result_gids,
                                                     FILE *file_group) {
  // gid_t gid;
  int i = 0;
  int entries = 0;
  int found = 0;

  size_t buflen = 4096;
  char buf[buflen];
  struct group gr, *grp;

  // Make sure we read from the beginning,
  rewind(file_group);
  char gid_str[16];
  while (1) {
    // Get entries from our cache file
    i = fgetgrent_r(file_group, &gr, buf, buflen, &grp);

    // Return on error/eof
    if (i) {
      ptrc("looped '%d' entries, fgetgrent_r returned %d", entries, i);
      break;
    }

    // Look for match
    for (int x = 0; grp->gr_mem[x]; x++) {
      pinf("matching user '%s' against group member '%s' in group '%s'", username,
           grp->gr_mem[x], grp->gr_name);

      if (strcmp(grp->gr_mem[x], username) == 0) {
        pinf("username '%s' found in group '%s'", username, grp->gr_name);
        snprintf(gid_str, sizeof(gid_str) - 1, "%d", grp->gr_gid);
        strcat(result_gids, gid_str);
        strcat(result_gids, ",");

        found = 1;
      }
    }

    entries++;
  }

  if (found == 1) {
    // Remove dangling comma,
    result_gids[strlen(result_gids) - 1] = '\0';
    pinf("gids founds '%s'", result_gids);
    return 1;
  }

  return 0;
}

int onelogin_get_auth_bearer(CURL *ch, struct curl_buffer *curl_buffer,
                             char *bearer, int token_auth_cap) {
  CURLcode ret;
  struct curl_slist *headers = NULL;
  char header_data[LENGTH_HEADER_DATA];
  char url[LENGTH_URL];

  pfnc(__func__);

  // Consruct url for getting the auth token
  snprintf(url, sizeof(url) - 1, "https://%s.onelogin.com/auth/oauth2/v2/token",
           config.onelogin_subdomain.value);

  // Not sure if I understand the onelogin api correctly, but as far as I'm
  // concerned I don't want my api keys to have more access rights than needed.
  // We need to types of access righs, one with "read users" permissions which
  // is used to query users and roles, and one with "auth capabilities" which
  // is used to verify the otp. Here we simply determine which api key to use.
  if (token_auth_cap == 1) {
    snprintf(header_data, sizeof(header_data) - 1,
             "Authorization: client_id:%s,client_secret:%s",
             config.onelogin_client_auth_only_id.value,
             config.onelogin_client_auth_only_secret.value);
  } else {
    snprintf(header_data, sizeof(header_data) - 1,
             "Authorization: client_id:%s,client_secret:%s",
             config.onelogin_client_read_id.value,
             config.onelogin_client_read_secret.value);
  }

  // Set headers content and post fields
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, header_data);
  curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(ch, CURLOPT_POSTFIELDS,
                   "{\"grant_type\": \"client_credentials\"}");

  // Do the call to onelogin
  pinf("trying to get onelogin authentication bearer (auth_capabilties=%i)",
       token_auth_cap);
  ret = curl_call(ch, curl_buffer, url);

  // Curl call finidshed, clean up headers and reset handle
  curl_slist_free_all(headers);
  curl_easy_reset(ch);

  // Check return
  if (ret != CURLE_OK) {
    pwrn("could not get authentication bearer for onelogin from '%s'", url);
    return 0;
  };

  // Check that we have a response
  if (curl_buffer->response == NULL) {
    pwrn("no data was returned from '%s'", url);
    return 0;
  }

  // Extract access token from supposed json response,
  ptrc("successfully got the following response from curl '%s'",
       curl_buffer->response);

  if (!extract_value_from_key(curl_buffer->response, "\"access_token\":\"",
                              "\"", bearer)) {
    pwrn("could not get authentication baerer");
    return 0;
  }

  // Reset curl headers so we are ready to reuse
  return 1;
}

int onelogin_get_enrolled_otps_for_user(CURL *ch,
                                        struct curl_buffer *curl_buffer,
                                        char *bearer, const uid_t user_id,
                                        Otps *otps) {
  CURLcode ret;
  struct curl_slist *headers = NULL;
  char header_data[LENGTH_HEADER_DATA];
  char url[LENGTH_URL];

  pfnc(__func__);

  // Construct url with authentication bearer
  snprintf(url, 255, "https://%s.onelogin.com/api/2/mfa/users/%lu/devices",
           config.onelogin_subdomain.value, (long unsigned int)user_id);
  snprintf(header_data, sizeof(header_data) - 1, "Authorization: bearer %s",
           bearer);
  pinf("->looking upasdfasdf otps for user with  id '%d'", user_id);

  // Set headers
  headers = curl_slist_append(headers, header_data);
  curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

  // Do the call to onelogin
  pinf("->looking up otps for user with  id '%d'", (long unsigned int)user_id);
  ret = curl_call(ch, curl_buffer, url);

  // Curl call finidshed, clean up headers
  curl_slist_free_all(headers);

  // Check return
  if (ret != CURLE_OK) {
    pwrn("could not get authentication bearer for onelogin from '%s'", url);
    return 0;
  };

  // Check that we have a response
  if (curl_buffer->response == NULL) {
    pwrn("no data was returned from '%s'", url);
    return 0;
  }

  // Extract access token from supposed json response,
  ptrc("successfully got the following response from curl '%s'",
       curl_buffer->response);

  // Split json on array elements
  char *strtokptr;
  char *token = strtok_r(curl_buffer->response, "}", &strtokptr);
  char value_from_extraction[256];
  int i = 0;

  // Split will generate a "]" at the end, so make the loop depend on that
  while (token != NULL) {
    ptrc("extracted '%s' from enrolled otps", token);

    if (strcmp(token, "]") == 0) {
      ptrc("no more otp devices found");
      break;
    }

    // Reset extraction str
    value_from_extraction[0] = '\0';

    // 1 ) Extract type_display_name
    extract_value_from_key(token, "\"type_display_name\":\"", "\"",
                           value_from_extraction);
    if (value_from_extraction[0] == '\0') {
      pwrn("could not extract 'type_display_name' from '%s'",
           value_from_extraction);
      goto next;
    }

    // The deafult OneLogin protect otp supports both push and code.
    // However they only return one device, so we need to manually add this
    // device. Why do you want to use the code if they support push you may ask
    // ? It actually happens that the "push-service" could be out-of-service
    // (this has actually happened), ie. you cant validate the otp via push.
    // However, as long the "service that validates the otp-code" is up, we can
    // use that as a fallback (ie. push will not work, but entering an otp
    // manually will). If both the "push-service" and the "service that
    // validates the otp-code" is down, we are screwed.
    if (strcmp(value_from_extraction, "OneLogin Protect") == 0 &&
        strstr(value_from_extraction, "[ PUSH ]") == NULL) {
      strcat(value_from_extraction, " [ PUSH ]");
      otps[i].onelogin_allows_for_push = 1;
    } else {
      //   // Disable this "hack" for all devices except the first
      //   "OneLoginProtect "
      otps[i].onelogin_allows_for_push = 0;
    }
    ptrc("extracted '%s' as device name", value_from_extraction);
    strcpy(otps[i].name, value_from_extraction);

    // 2 ) Extract device_id
    extract_value_from_key(token, "\"device_id\":\"", "\"",
                           value_from_extraction);
    if (value_from_extraction[0] == '\0') {
      pwrn("could not extract 'device_id' from '%s'", value_from_extraction);
      goto next;
    }
    if ((int32_t)util_strtoul(value_from_extraction) < 0) {
      pwrn("could not convert '%s' into an unsigned long int",
           value_from_extraction);
      goto next;
    }
    pinf("extracted '%i' as device id", util_strtoul(value_from_extraction));
    otps[i].id = util_strtoul(value_from_extraction);

    // 3 Extract default
    extract_value_from_key(token, "\"default\":", "", value_from_extraction);
    if (value_from_extraction[0] == '\0') {
      pwrn("could not extract 'default' from '%s'", value_from_extraction);
      goto next;
    }
    pinf("extracted '%c' as default", util_strtoul(value_from_extraction));
    if (config_is_value_true(value_from_extraction)) {
      otps[i]._default = 1;
    }

    // Make a copy of our "OneLogin Protect" service, and disable push
    if (strcmp(otps[i].name, "OneLogin Protect [ PUSH ]") == 0) {
      strcpy(otps[i + 1].name, "OneLogin Protect [ CODE ]");
      otps[i + 1].id = otps[i].id;
      otps[i + 1]._default = 0;
      otps[i + 1].onelogin_allows_for_push = 0;
      i++;
    }

  next:
    i++;
    token = strtok_r(NULL, "}", &strtokptr);
  }

  // Move default otp device to first in the list, not sure how they are
  // returned from onelogin.
  int index_default = 0;
  for (unsigned long b = 0; b < NUM_OTP_DEVICES; b++) {
    if (strcmp(otps[b].name, "") == 0) {
      continue;
    }

    if (otps[b]._default) {
      ptrc("otp device with name '%s' is default", otps[b].name);
      index_default = b;
    }

    ptrc(
        "otp device, name : %s, id : %i, onelogin_allows_for_push : %i, "
        "default : %i, index %i",
        otps[b].name, otps[b].id, otps[b].onelogin_allows_for_push,
        otps[b]._default, b);
  }

  // Make sure the default otp is first in array. Hopefully nobody has
  // NUM_OTP_DEVICES otp-devices.
  otps[NUM_OTP_DEVICES - 1] = otps[0];
  otps[0] = otps[index_default];
  otps[index_default] = otps[NUM_OTP_DEVICES - 1];
  otps[NUM_OTP_DEVICES - 1].name[0] = '\0';

  return 1;
}

int onelogin_get_user(CURL *ch, struct curl_buffer *curl_buffer, char *bearer,
                      const char *user_id, char *user_data) {
  CURLcode ret;
  struct curl_slist *headers = NULL;
  char header_data[LENGTH_HEADER_DATA];
  char url[LENGTH_URL];

  pfnc(__func__);

  // Construct url with authentication bearer
  snprintf(url, sizeof(url) - 1, "https://%s.onelogin.com/api/2/users/%s",
           config.onelogin_subdomain.value, user_id);
  snprintf(header_data, sizeof(header_data) - 1, "Authorization: bearer %s",
           bearer);

  // Set headers
  headers = curl_slist_append(headers, header_data);
  curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

  // Do the call to onelogin
  pinf("->looking up user with id '%s'", user_id);
  ret = curl_call(ch, curl_buffer, url);

  // Curl call finidshed, clean up headers
  curl_slist_free_all(headers);

  // Check return
  if (ret != CURLE_OK) {
    pwrn("could not get authentication bearer for onelogin from '%s'", url);
    return 0;
  };

  // Check that we have a response
  if (curl_buffer->response == NULL) {
    pwrn("no data was returned from '%s'", url);
    return 0;
  }

  // Extract access token from supposed json response,
  ptrc("successfully got the following response from curl '%s'",
       curl_buffer->response);

  // Copy response to the caller allocated char
  strncpy(user_data, curl_buffer->response, 32767);
  return 1;
}

// Function used by our nss-module to lookup a user
int onelogin_get_users_with_role(CURL *ch, struct curl_buffer *curl_buffer,
                                 char *bearer, const char *rolename,
                                 char (*role_members)[512],
                                 char (*role_ids)[512], char *users,
                                 int role_index) {
  CURLcode ret;
  struct curl_slist *headers = NULL;
  char header_data[LENGTH_HEADER_DATA];
  char url[LENGTH_URL];

  pfnc(__func__);

  // Construct url with authentication bearer
  snprintf(url, sizeof(url) - 1,
           "https://%s.onelogin.com/api/2/roles?name=%s&fields=name,users,id",
           config.onelogin_subdomain.value, rolename);
  snprintf(header_data, sizeof(header_data) - 1, "Authorization: bearer %s",
           bearer);

  // Set headers
  headers = curl_slist_append(headers, header_data);
  curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

  // Do the call to onelogin
  pinf("->looking up users with role '%s'", rolename);
  ret = curl_call(ch, curl_buffer, url);

  // Curl call finidshed, clean up headers
  curl_slist_free_all(headers);

  // Check return
  if (ret != CURLE_OK) {
    pwrn("could not get users with role '%s' from '%s'", rolename, url);
    return 0;
  };

  // Check that we have a response
  if (curl_buffer->response == NULL) {
    pwrn("no data was returned from '%s'", url);
    return 0;
  }

  // Extract access token from supposed json response,
  ptrc("successfully got the following response from curl '%s'",
       curl_buffer->response);

  // Parse comma separated user string, and append to user list, it not already
  // present (a user may have multiple roles)
  char *ptr_roles;
  char *strtok_ptr_roles;
  char buf[4096];
  char rolename_exact[256];
  sprintf(rolename_exact, "\"%s\"", rolename);

  ptr_roles = strtok_r(curl_buffer->response, "}", &strtok_ptr_roles);
  while (ptr_roles != NULL) {
    pinf("part of string is '%s'", ptr_roles);
    pinf("comparing with role '%s'", rolename_exact);

    // If we have the json string that corresponds to our role
    if (strstr(ptr_roles, rolename_exact) != NULL) {
      // Extract the role id, and put in 2d array
      if (!extract_value_from_key(ptr_roles, "\"id\":", ",", buf)) {
        pwrn("could not extract id from '%s'", ptr_roles);
        return 0;
      }
      pinf("successfully extracted id : %s", buf);
      strncpy(role_ids[role_index], buf, 511);

      // Extract all users for this role,
      if (!extract_value_from_key(ptr_roles, "\"users\":[", "]", buf)) {
        pwrn("could not find any users with role '%s'", rolename);
        return 0;
      }

      // Put all users that have this specific role in a 2d array. We need this
      // to create our local group membership
      strncpy(role_members[role_index], buf, 511);

      // Parse comma separated user string, and append to user list, if not
      // already present (a user may have multiple roles)
      char *ptr_userid = NULL;
      char *strtok = NULL;

      ptr_userid = strtok_r(buf, ",", &strtok);
      while (ptr_userid != NULL) {
        // If userid is not found in list of users, append it
        if (strstr(users, ptr_userid) == NULL) {
          strncat(users, ptr_userid, sizeof(buf) - 1);
          strncat(users, ",", 2);
          pinf("appending userid '%s' to list of users", ptr_userid);
        } else {
          pinf("userid '%s' already added", ptr_userid);
        }
        ptr_userid = strtok_r(NULL, ",", &strtok);
      }
    }

    // Update token ptr
    ptr_roles = strtok_r(NULL, "}", &strtok_ptr_roles);
  }

  return 1;
}

int onelogin_verify_password(CURL *ch, struct curl_buffer *curl_buffer,
                             char *bearer, const char *name,
                             char *user_input_password) {
  CURLcode ret;
  struct curl_slist *headers = NULL;
  char header_data[LENGTH_HEADER_DATA];
  char header_data_[LENGTH_HEADER_DATA];
  char username_or_email[255];
  char url[LENGTH_URL];

  pfnc(__func__);

  // Construct url with authentication bearer
  snprintf(url, sizeof(url) - 1, "https://%s.onelogin.com/api/1/login/auth",
           config.onelogin_subdomain.value);
  snprintf(header_data, sizeof(header_data) - 1, "Authorization: bearer %s",
           bearer);

  if (strstr(name, "@") == NULL) {
    ptrc("appending domain '%s' to username '%s'",
         config.onelogin_user_domain_append.value, name);
    snprintf(username_or_email, 256 - 1, "%s@%s", name,
             config.onelogin_user_domain_append.value);
  } else {
    strncpy(username_or_email, name, sizeof(username_or_email) - 1);
  }

  char post[4096];
  snprintf(post, sizeof(post) - 1,
           "{ \"username_or_email\" : \"%s\", \"password\" : \"%s\", "
           "\"subdomain\" : \"%s\"}",
           username_or_email, user_input_password,
           config.onelogin_subdomain.value);
  snprintf(header_data_, sizeof(header_data_) - 1,
           "Content-Type: application/json");

  // Set headers
  headers = curl_slist_append(headers, header_data);
  headers = curl_slist_append(headers, header_data_);
  curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

  // Do the actual curl call,
  curl_easy_setopt(ch, CURLOPT_POSTFIELDS, post);

  // Do the call to onelogin
  pinf("->verifying password for user '%s'", username_or_email);
  ret = curl_call(ch, curl_buffer, url);

  // Curl call finidshed, clean up headers, and reset to get req
  curl_slist_free_all(headers);
  curl_easy_setopt(ch, CURLOPT_HTTPGET, 1L);

  // Check return
  if (ret != CURLE_OK) {
    pwrn("could not get authentication bearer for onelogin from '%s'", url);
    return 0;
  };

  // Check that we have a response
  if (curl_buffer->response == NULL) {
    pwrn("no data was returned from '%s'", url);
    return 0;
  }

  // Extract access token from supposed json response,
  ptrc("successfully got the following response from curl '%s'",
       curl_buffer->response);

  char value_from_extraction[256];

  // Extract the status from the otp-activation,
  if (!extract_value_from_key(curl_buffer->response, "\"type\":\"", "\"",
                              value_from_extraction)) {
    pwrn("could not extract status from password verification response");
    return 0;
  }

  if (strcmp(value_from_extraction, "success") == 0) {
    pinf("successfully verified password for user '%s'", username_or_email);
    return 1;
  }
  return 0;
}

int onelogin_verify_otp(CURL *ch, struct curl_buffer *curl_buffer, char *bearer,
                        Otps *otp, char *user_input_otp, const uid_t user_id,
                        const char *name) {
  pfnc(__func__);
  pinf("verifying otp device '%s' for userid '%i' with token '%s'", otp->name,
       user_id, user_input_otp);

  CURLcode ret;
  struct curl_slist *headers = NULL;
  char header_data[LENGTH_HEADER_DATA];
  char header_data_[LENGTH_HEADER_DATA];
  char url[LENGTH_URL + 256];

  snprintf(url, sizeof(url) - 1,
           "https://%s.onelogin.com/api/2/mfa/users/%i/verifications",
           config.onelogin_subdomain.value, user_id);

  snprintf(header_data, sizeof(header_data) - 1, "Authorization: bearer %s",
           bearer);
  snprintf(header_data_, sizeof(header_data_) - 1,
           "Content-Type: application/json");

  headers = curl_slist_append(headers, header_data);
  headers = curl_slist_append(headers, header_data_);
  curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

  char post[4096];
  if (otp->onelogin_allows_for_push != 1) {
    snprintf(post, sizeof(post) - 1,
             "{ \"otp\" : \"%s\", \"device_id\" : \"%d\"}", user_input_otp,
             otp->id);
  } else {
    snprintf(post, sizeof(post) - 1, "{\"device_id\" : %i}", otp->id);
  }

  ptrc("will post '%s' to verify otp for user '%s'", post, name);

  // Do the actual curl call,
  curl_easy_setopt(ch, CURLOPT_POSTFIELDS, post);
  ret = curl_call(ch, curl_buffer, url);

  // Check return
  if (ret != CURLE_OK) {
    pwrn("could not activate otp for user '%s' at url '%s'", name, url);
    return 0;
  };

  // Check that we have a response
  if (curl_buffer->response == NULL) {
    pwrn("no data was returned from '%s'", url);
    return 0;
  }

  // Extract access token from supposed json response,
  ptrc("successfully got the following response from curl '%s'",
       curl_buffer->response);

  char value_from_extraction[256];

  // If we use an otp-code
  if (otp->onelogin_allows_for_push != 1) {
    // Extract the status from the otp-activation,
    if (!extract_value_from_key(curl_buffer->response, "\"status\":\"", "\"",
                                value_from_extraction)) {
      pwrn("could not extract status from otp activation response");
      return 0;
    }

    // Check if otp activation was 'accepted'
    ptrc("extracted status '%s' from otp activation", value_from_extraction);
    if (strcmp(value_from_extraction, "accepted") == 0) {
      return 1;
    }
    pwrn("extracted response from otp-actication was '%s'",
         value_from_extraction);
    return 0;
  } else {
    // Here we use the push functionality, so we get an id back in our response.
    // That id is then used in another request, where we will poll the endpoint
    // and wait for 1 ) user accepted, 2 ) timeout.

    // Extract the id from the otp-activation,
    if (!extract_value_from_key(curl_buffer->response, "\"id\":\"", "\"",
                                value_from_extraction)) {
      pwrn("could not extract id from otp activation response");
      return 0;
    }
    ptrc("extracted id '%s' from otp activation", value_from_extraction);

    snprintf(url, sizeof(url) - 1,
             "https://%s.onelogin.com/api/2/mfa/users/%i/verifications/%s",
             config.onelogin_subdomain.value, user_id, value_from_extraction);

    int seconds = 0;
    int seconds_allowed_wait = 15;
    int interval = 2;

    curl_easy_setopt(ch, CURLOPT_HTTPGET, 1L);

    while (1) {
      ptrc("verifying otp-activation with id '%s'", value_from_extraction);
      ret = curl_call(ch, curl_buffer, url);

      // Check return
      if (ret != CURLE_OK) {
        pwrn("could not verify otp activation for user '%s' at url '%s'", name,
             url);
        return 0;
      };

      // Check that we have a response
      if (curl_buffer->response == NULL) {
        pwrn("no data was returned from '%s'", url);
        return 0;
      }

      // Extract the status from the otp-activation,
      value_from_extraction[0] = '\0';
      if (!extract_value_from_key(curl_buffer->response, "\"status\":\"", "\"",
                                  value_from_extraction)) {
        pwrn("could not extract status from otp activation response");
        // return 0;
      }

      // Check if otp activation was 'accepted'
      ptrc("extracted status '%s' from otp activation", value_from_extraction);
      if (strcmp(value_from_extraction, "accepted") == 0) {
        return 1;
      }

      if (seconds >= seconds_allowed_wait) {
        pwrn("user did not accept otp within given timeframe (%s seconds)",
             seconds_allowed_wait);
        return 0;
      }

      sleep(interval);
      seconds += interval;
    }
  }

  return 0;
}

signed int util_strtoul(const char *str) {
  char *endptr;
  signed long val;
  errno = 0;

  // Check for non digits
  for (unsigned int i = 0; i < strlen(str); i++) {
    if (!isdigit(str[i])) {
      perr(
          "failed to convert '%s' to an long int, character '%c' is not a "
          "digit",
          str, str[i]);
      return -1;
    }
  }

  // If str is empty,
  if (str[0] == '\0') {
    perr("failed to convert '%s' to an long int, input is empty", str);
    return -1;
  }

  // If we only have digits (0-9), try to convert
  val = strtol(str, &endptr, 0);

  // Check errno for possible errors
  if (errno != 0) {
    perr("failed to convert '%s' to an long int (%s)", str, strerror(errno));
    return -1;
  }

  // Should not be possible since we already checked for this
  if (endptr == str) {
    perr(
        "failed to convert '%s' to an long int since no digits were found "
        "(%s)",
        str, strerror(errno));
    return -1;
  }
  return val;
}

void util_print_pw_str(char *str, struct passwd *pw) {
  pinf("%s '%s:x:%d:%d:%s:%s:%s'", str, pw->pw_name, pw->pw_uid, pw->pw_gid,
       pw->pw_gecos, pw->pw_dir, pw->pw_shell);
}
