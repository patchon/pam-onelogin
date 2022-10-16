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

#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include <nss.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <shadow.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../headers/config.h"
#include "../headers/logging.h"
#include "../headers/onelogin.h"

void pam_onelogin_build_otp_message(char *msg_otp_devices, Otps *otps,
                                    int *valid_otp_devices) {
  char buf_tmp[4096];
  int cnt = 0;

  for (unsigned long i = 0; i < NUM_OTP_DEVICES; i++) {
    if (strcmp(otps[i].name, "") == 0) {
      continue;
    }

    ptrc("name : %s, id : %i, allows_for_push : %i, default : %i, index : %i",
         otps[i].name, otps[i].id, otps[i].onelogin_allows_for_push,
         otps[i]._default, i);

    // Construct temporary str
    if (otps[i]._default) {
      snprintf(buf_tmp, 4095, "[ %lu ] %s (default) \n", i, otps[i].name);
    } else {
      snprintf(buf_tmp, 4095, "[ %lu ] %s\n", i, otps[i].name);
    }

    // Append to final msg
    strcat(msg_otp_devices, buf_tmp);
    cnt++;
    (*valid_otp_devices) = cnt;
  }

  strcat(msg_otp_devices, "\nPlease select OTP device : ");
  ptrc("constructed the following otp-selection-string \n'%s'",
       msg_otp_devices);
}

int pam_onelogin_get_input(char *user_input_otp, pam_handle_t *pamh,
                           const char *name, int len, char *msg_,
                           int msg_style) {
  struct pam_message msg = {.msg_style = msg_style, .msg = msg_};
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;

  int ret = 0;
  ret = converse(pamh, 1, &msgs, &resp);

  if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    pwrn("input from user '%s' is empty", name);
    return 0;
  } else {
    strncpy(user_input_otp, resp->resp, len - 1);
    free(resp);
    return 1;
  }
}

int pam_onelogin_show_otp_devices_and_get_input(char *msg_otp_devices,
                                                int valid_otp_devices,
                                                int *selected_otp_device,
                                                pam_handle_t *pamh,
                                                const char *name) {
  struct pam_message msg = {.msg_style = PAM_PROMPT_ECHO_ON,
                            .msg = msg_otp_devices};
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;

  char input_user_otp_selection[4] = "";
  int ret = 0;
  int errors = 0;
  int errors_allowed = 3;

  while (1) {
    errors++;
    pinf("here");
    ret = converse(pamh, 1, &msgs, &resp);

    if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
        *resp->resp == '\000') {
      ptrc(
          "input from user '%s' is empty, defaulting otp device index to "
          "'0'");
      strncpy(input_user_otp_selection, "0",
              sizeof(input_user_otp_selection) - 1);
    } else {
      strncpy(input_user_otp_selection, resp->resp,
              sizeof(input_user_otp_selection) - 1);
    }

    int val = util_strtoul(input_user_otp_selection);
    if (val < 0 || val > valid_otp_devices - 1) {
      pwrn("input '%i' from user '%s' is not valid, user has '%i' more tries",
           val, name, errors_allowed - errors);
      if (errors == errors_allowed) {
        perr(
            "user '%s' entered the wrong option for '%i' times (max allowed "
            "is "
            "'%i'), returning PAM_AUTH_ERROR",
            name, errors, errors_allowed);
        return 0;
      }
      continue;
    }

    pinf("input '%s' from user '%s' passes validation",
         input_user_otp_selection, name);
    (*selected_otp_device) = val;

    if (resp) {
      free(resp);
    }
    break;
  }
  return 1;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  // Open config, will exit on failure
  if (config.parsed.value != 1) config_parse_file(CONFIG_FNAME);

  pfnc(__func__);

  const char *name;
  struct passwd pw;
  int ret;
  char bearer[LENGTH_BEARER] = {'\0'};
  char bearer_auth_cap[LENGTH_BEARER] = {'\0'};
  CURL *ch;
  FILE *file_passwd;

  // Init otp-struct with empty values
  struct Otps otps[NUM_OTP_DEVICES];
  for (unsigned long i = 0; i < NUM_OTP_DEVICES; i++) {
    otps[i].name[0] = '\0';
    otps[i].id = 0;
    otps[i].onelogin_allows_for_push = 0;
    otps[i]._default = 0;
  }

  // Open cache
  if (!onelogin_cache_open(&file_passwd, CACHE_FILE_PASSWD, "r")) {
    perr("error when opening cache file");
    return PAM_AUTH_ERR;
  }

  // Get current user
  ret = pam_get_user(pamh, &name, "Username: ");
  if (ret != PAM_SUCCESS) {
    perr("could not get user from pam");
    return PAM_AUTH_ERR;
  }

  pinf("user '%s' found, contintuing in pam", name);

  if (!onelogin_fetch_user_from_cache(name, 0, &pw, file_passwd)) {
    perr("user not in onelogin cache, returning from module");
    return PAM_AUTH_ERR;
  };

  // Create pointer to curl buffer for returned data and allocate memory
  struct curl_buffer *curl_buffer =
      (struct curl_buffer *)malloc(sizeof(struct curl_buffer));

  // Init curl, hardcode 10 second timeout for now
  if ((ch = curl_easy_init()) == NULL) {
    perr("could not initialze curl");
    goto cleanup;
  }
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, CURL_TIMEOUT);

  // Get onelogin authentication bearer
  if (!onelogin_get_auth_bearer(ch, curl_buffer, bearer, 0)) {
    perr("no authentication bearer for onelogin available");
    goto cleanup;
  }

  // Get onelogin authentication bearer, auth capabilites this time
  if (!onelogin_get_auth_bearer(ch, curl_buffer, bearer_auth_cap, 1)) {
    perr("no authentication bearer for onelogin available");
    goto cleanup;
  }

  // Set the timeout again since the curl handle was reset
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, CURL_TIMEOUT);

  char user_input_password[128] = {'\0'};
  char user_input_msg_password[64] =
      "\n\nEnter your OneLogin Password (not OTP) :";
  if (!pam_onelogin_get_input(user_input_password, pamh, name,
                              sizeof(user_input_password),
                              user_input_msg_password, PAM_PROMPT_ECHO_OFF)) {
    goto cleanup;
  }

  if (!onelogin_verify_password(ch, curl_buffer, bearer_auth_cap, name,
                                user_input_password)) {
    goto cleanup;
  }

  // Get enrolled otps for the user
  if (!onelogin_get_enrolled_otps_for_user(ch, curl_buffer, bearer, pw.pw_uid,
                                           otps)) {
    perr("error getting otp decices for user '%s'", pw.pw_name);
    goto cleanup;
  }

  // Build string to present the devices to the user
  char msg_otp_devices[4096] = "\n";
  int valid_otp_devices = 0;
  int selected_otp_device = 0;
  pam_onelogin_build_otp_message(msg_otp_devices, otps, &valid_otp_devices);
  ptrc("valid otp devices '%i'", valid_otp_devices);

  // Present otp devices and get input from user
  if (!pam_onelogin_show_otp_devices_and_get_input(
          msg_otp_devices, valid_otp_devices, &selected_otp_device, pamh,
          name)) {
    goto cleanup;
  }

  ptrc("selected otp device is '%i'", selected_otp_device);

  char user_input_otp[128] = {'\0'};
  char user_input_msg_otp[64] = "\n\nEnter your OTP :";
  if (otps[selected_otp_device].onelogin_allows_for_push != 1) {
    if (!pam_onelogin_get_input(user_input_otp, pamh, name,
                                sizeof(user_input_otp), user_input_msg_otp,
                                PAM_PROMPT_ECHO_ON)) {
      goto cleanup;
    }
    pinf("user '%s' entered otp '%s'", name, user_input_otp);
  }

  // Set the timeout again since the curl handle was reset
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, CURL_TIMEOUT);

  // Get here, we have a valid otp-device to verify
  if (onelogin_verify_otp(ch, curl_buffer, bearer_auth_cap,
                          &otps[selected_otp_device], user_input_otp, pw.pw_uid,
                          name)) {
    free(curl_buffer);
    return PAM_SUCCESS;
  }

cleanup:
  free(curl_buffer);
  return PAM_AUTH_ERR;

  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
}

int converse(pam_handle_t *pamh, int nargs, const struct pam_message **message,
             struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }

  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  pfnc(__func__);

  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  pfnc(__func__);

  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  pfnc(__func__);

  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
  pfnc(__func__);

  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  pfnc(__func__);

  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}
