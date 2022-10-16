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

#ifndef FUNCTIONS_ONELOGIN_INCLUDED
#define FUNCTIONS_ONELOGIN_INCLUDED

#include <curl/curl.h>
#include <grp.h>
#include <pwd.h>
#include <security/pam_appl.h>

#include "config.h"
#include "curler.h"

#define CACHE_FILE_PASSWD "/etc/pam-onelogin/.cache_passwd"
#define CACHE_FILE_GROUP "/etc/pam-onelogin/.cache_group"
#define NUM_OTP_DEVICES 16

// Struct for handling otps
typedef struct Otps {
  char name[256];
  int id;
  int _default;
  int onelogin_allows_for_push;
} Otps;

int onelogin_cache_open(FILE **file_descriptor, char *file_to_open,
                        char *file_mode);

int onelogin_cache_close(FILE **file);

int onelogin_fetch_user_from_cache(const char *thing_to_lookup, int uid,
                                   struct passwd *p, FILE *file_passwd);

int onelogin_fetch_group_from_cache(const char *thing_to_lookup, int lookup_gid,
                                    struct group *g, FILE *file_group);

int onelogin_fetch_gids_belonging_to_user_from_cache(const char *username,
                                                     char *result_gids,
                                                     FILE *file_group);

int onelogin_get_auth_bearer(CURL *ch, struct curl_buffer *curl_buffer,
                             char *bearer, int token_auth_cap);

int onelogin_get_user(CURL *ch, struct curl_buffer *curl_buffer, char *bearer,
                      const char *user_id, char *user_data);

int onelogin_get_users_with_role(CURL *ch, struct curl_buffer *curl_buffer,
                                 char *bearer, const char *rolename,
                                 char (*role_members)[512],
                                 char (*role_ids)[512], char *users,
                                 int role_index);

int onelogin_get_enrolled_otps_for_user(CURL *ch,
                                        struct curl_buffer *curl_buffer,
                                        char *bearer, const uid_t user_id,
                                        Otps *otps);

void pam_onelogin_build_otp_message(char *msg_otp_devices, Otps *otps,
                                    int *valid_otp_devices);

int pam_onelogin_show_otp_devices_and_get_input(char *msg_otp_devices,
                                                int valid_otp_devices,
                                                int *selected_otp_device,
                                                pam_handle_t *pamh,
                                                const char *name);
int pam_onelogin_get_input(char *user_input_otp, pam_handle_t *pamh,
                           const char *name, int len, char *msg, int msg_style);

int onelogin_verify_otp(CURL *ch, struct curl_buffer *curl_buffer, char *bearer,
                        Otps *otp, char *user_input_otp, const uid_t user_id,
                        const char *name);

int onelogin_verify_password(CURL *ch, struct curl_buffer *curl_buffer,
                             char *bearer, const char *name,
                             char *user_input_password);

signed int util_strtoul(const char *str);
void util_print_pw_str(char *str, struct passwd *pw);
int converse(pam_handle_t *pamh, int nargs, const struct pam_message **message,
             struct pam_response **response);
#endif
