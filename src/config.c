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

#include "headers/config.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "headers/logging.h"

char config_valid_options[11][64] = {
    "auto_add_group_to_user",
    "disable_user_password_verification",
    "onelogin_client_auth_only_id",
    "onelogin_client_auth_only_secret",
    "onelogin_client_read_id",
    "onelogin_client_read_secret",
    "onelogin_region",
    "onelogin_subdomain",
    "onelogin_user_domain_append",
    "onelogin_user_roles",
    "parsed",
};

struct Config config;

void config_parse_file(const char* fname) {
  char line[512] = "";
  int multi_line_parse = 0;
  errno = 0;

  FILE* file = fopen(fname, "r");
  if (file == NULL) {
    perr("could not open %s (%s)", fname, strerror(errno));
    exit(errno);
  }

  // Do crude parsing to see if we have enabled any debug
  while (fgets(line, sizeof(line), file)) {
    line[strcspn(line, "\n")] = 0;
    if (!isalpha(line[0])) {
      continue;
    }
    if (strstr(line, "trace") != NULL) {
      if (strstr(line, "true") != NULL) {
        config.trace.value = 1;
        ptrc("enabled trace");
      }
    }
    if (strstr(line, "debug") != NULL) {
      if (strstr(line, "true") != NULL) {
        config.debug.value = 1;
        pinf("enabled debug");
      }
    }
    if (strstr(line, "log_stdout") != NULL) {
      if (strstr(line, "true") != NULL) {
        config.log_stdout.value = 1;
        pinf("enabled stdout");
      }
    }
    if (strstr(line, "log_syslog") != NULL) {
      if (strstr(line, "true") != NULL) {
        config.log_syslog.value = 1;
        pinf("enabled syslog");
      }
    }
  }

  // Read file again and do some more "thourough parsing" (although, still very
  // crude)
  rewind(file);
  while (fgets(line, sizeof(line), file)) {
    line[strcspn(line, "\n")] = 0;
    config_parse_line(line, &multi_line_parse);
  }

  fclose(file);

  // Remove last comma from comma-separated-string we've created from the
  // multi-line-array-element option (onelogin_user_roles)
  config.onelogin_user_roles
      .value[strlen(config.onelogin_user_roles.value) - 1] = '\0';

  // Set parsed attribute dummy. We check this value later to determine if
  // file is parsed already.
  config.parsed.value = 1;

  pinf("finished parsing file");
  pinf("config set as ");
  pinf("- auto_add_group_to_user : '%s'", config.auto_add_group_to_user.value);
  pinf("- disable_user_password_verification : '%d'",
       config.disable_user_password_verification.value);
  pinf("- debug : '%i'", config.debug.value);
  pinf("- log_stdout : '%i'", config.log_stdout.value);
  pinf("- log_syslog : '%i'", config.log_syslog.value);
  pinf("- onelogin_client_read_id : '%s'",
       config.onelogin_client_read_id.value);
  pinf("- onelogin_client_read_secret : '%s'",
       config.onelogin_client_read_secret.value);
  pinf("- onelogin_client_auth_only_id : '%s'",
       config.onelogin_client_auth_only_id.value);
  pinf("- onelogin_client_auth_only_secret : '%s'",
       config.onelogin_client_auth_only_secret.value);
  pinf("- onelogin_region : '%s'", config.onelogin_region.value);
  pinf("- onelogin_subdomain : '%s'", config.onelogin_subdomain.value);
  pinf("- onelogin_user_domain_append : '%s'",
       config.onelogin_user_domain_append.value);
  pinf("- onelogin_user_roles : '%s'", config.onelogin_user_roles.value);
  pinf("- parsed : '%d'", config.parsed.value);
  pinf("- trace : '%d'", config.trace.value);
}

void config_parse_line(char* line, int* multi_line_parse) {
  // Set up tmp buf and pointers for key / values
  char buf[512] = "";
  char* key = NULL;
  char* val = NULL;

  ptrc("parsing line '%s'", line);
  strcpy(buf, line);

  if (!isalpha(line[0])) {
    // If the line doesn't start with an alpha char, check if int is set to
    // handle special parsing. If the flag is set, we first make sure the line
    // starts with an indentaion, or a '-', ie. array objects.
    if (*multi_line_parse == 1) {
      // If the line doesn't seem to be an array element (ie. doesn't start
      // with an indentation nor a dash), abort special parsing and go back to
      // "regular" line parsing
      if (line[0] != ' ' && line[0] != '-') {
        ptrc("special parsing considered done");
        *multi_line_parse = 0;
        return;
      }

      // If we however encounter something that looks like an array element,
      // parse it similar to how we parse "regular" lines. Split the key to
      // everything before '-', and val to everthing after. The key here is not
      // used and is just the spaces/indentation part of the line
      key = strtok(buf, " ");
      val = strtok(NULL, " ");
      // Handle array element that is not indented,
      if (val == NULL) {
        val = key;
      }
      ptrc("parsed line '%s' into, key: '%s', val: '%s'", line, key, val);
      if (!config_validate_option("onelogin_user_roles", val)) {
        ptrc("line '%s' doesn't contain a valid option, ignoring", line);
        return;
      }
    } else {
      // If we are not in "special parsing mode" and the line doesn't start with
      // an alpha char, just consider it as invalid
      ptrc("ignoring line '%s'", line);
    }
  } else {
    // If the line starts with an alpha char, split the key to everything before
    // colon, val to everything after
    key = strtok(buf, ":");
    val = strtok(NULL, "");
    ptrc("parsed line '%s' into, key: '%s', val: '%s'", line, key, val);

    // If we have an option that requires multiline parsing, set flag
    if (strcmp(key, "onelogin_user_roles") == 0) {
      ptrc("foound special key");
      *multi_line_parse = 1;
    } else {
      // Otherwise, parse line "regular style" (single line)
      if (!config_validate_option(key, val)) {
        ptrc("line '%s' doesn't contain a valid option, ignoring", line);
        return;
      }
    }
  }
}

int config_validate_option(char* key, char* val) {
  // Loop valid options
  for (unsigned int i = 0; i < sizeof(config_valid_options) / 64; i++) {
    // Check if key is a valid option
    ptrc("comparing option '%s' with key '%s'", config_valid_options[i], key);
    if (strcmp(key, config_valid_options[i]) == 0) {
      config_validate_option_value(config_valid_options[i], val);
      return 1;
    } else {
      ptrc("key '%s' is not eqaul to '%s', continuing", key,
           config_valid_options[i]);
    }
  }
  return 0;
}

void config_validate_option_value(const char* option, char* value) {
  // Start by checking if the value is null (ie. something is wrong)
  if (value == NULL) {
    perr("option '%s' has an empty value", option);
    exit(1);
  }

  // Then, check if string is empty (ie. value is only spaces)
  unsigned int spaces = 0;
  for (int i = 0; value[i] != 0; i++) {
    if (isspace(value[i])) {
      spaces++;
    }
  }

  if (spaces == strlen(value)) {
    perr("option '%s' is an empty string", option);
    exit(1);
  }

  // Get here, it should be relative safe to save the values into our config.
  // Loop value to get rid of leading spaces
  for (int i = 0; value[i] != 0; i++) {
    // First character that is not a space is considered as start of value
    if (value[i] != ' ') {
      ptrc("setting option '%s' to '%s'", option, &value[i]);
      // Check for specific option and set its corresponding value in
      // config struct
      if (strcmp(option, "auto_add_group_to_user") == 0) {
        strncpy(config.auto_add_group_to_user.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);
      } else if (strcmp(option, "disable_user_password_verification") == 0) {
        if (config_is_value_true(&value[i])) {
          config.disable_user_password_verification.value = 1;
        } else {
          config.disable_user_password_verification.value = 0;
        }
      } else if (strcmp(option, "onelogin_client_auth_only_id") == 0) {
        config_is_value_length_ok("onelogin_client_auth_only_id", &value[i],
                                  128);
        strncpy(config.onelogin_client_auth_only_id.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);

      } else if (strcmp(option, "onelogin_client_auth_only_secret") == 0) {
        config_is_value_length_ok("onelogin_client_auth_only_secret", &value[i],
                                  128);
        strncpy(config.onelogin_client_auth_only_secret.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);

      } else if (strcmp(option, "onelogin_client_read_id") == 0) {
        config_is_value_length_ok("onelogin_client_read_id", &value[i], 128);
        strncpy(config.onelogin_client_read_id.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);

      } else if (strcmp(option, "onelogin_client_read_secret") == 0) {
        config_is_value_length_ok("onelogin_client_read_secret", &value[i],
                                  128);
        strncpy(config.onelogin_client_read_secret.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);

      } else if (strcmp(option, "onelogin_region") == 0) {
        strncpy(config.onelogin_region.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);
      } else if (strcmp(option, "onelogin_subdomain") == 0) {
        config_is_value_length_ok("onelogin_subdomain", &value[i], 64);
        strncpy(config.onelogin_subdomain.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);
      } else if (strcmp(option, "onelogin_user_domain_append") == 0) {
        strncpy(config.onelogin_user_domain_append.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);
      } else if (strcmp(option, "onelogin_user_roles") == 0) {
        // If number of roles needed, creates a longer string than we have
        // allocated for, just print an error and exit
        if (strlen(config.onelogin_user_roles.value) + strlen(&value[i]) >
            254) {
          pinf("to many roles specified, file a bug report");
          pinf("we have only allocated %d bytes, but we need %d",
               sizeof(config.onelogin_user_roles.value),
               strlen(config.onelogin_user_roles.value) + strlen(&value[i]));
          exit(1);
        }
        strncat(config.onelogin_user_roles.value, &value[i],
                sizeof(config.auto_add_group_to_user.value) - 1);
        strcat(config.onelogin_user_roles.value, ",");
      } else {
        // Should not get here
        perr("option '%s' is not a valid option", option);
        exit(1);
      }
      break;
    }
  }
}

int config_is_value_true(char* value) {
  // Create copy to be able to print original str
  char tmp[256] = "";
  strncpy(tmp, value, 255);

  // Lowercase first char, compare and return
  tmp[0] = tolower(tmp[0]);
  if (strcmp(tmp, "true") == 0) {
    ptrc("value '%s' is considered to be 'true'", value);
    return 1;
  } else if (strcmp(value, "false") == 0) {
    ptrc("value '%s' is considered to be 'false'", value);
    return 0;
  }

  perr("value '%s' is invalid (only true/false allowed)", value);
  exit(1);
}

void config_is_value_length_ok(char* opt, char* str, unsigned int max_length) {
  if (strlen(str) > max_length) {
    perr(
        "value for option '%s' can not be longer than %d characters "
        "(%s is %d characters)",
        opt, max_length, str, strlen(str));
    exit(1);
  }
}
