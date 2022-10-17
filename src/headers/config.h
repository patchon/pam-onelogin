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

#ifndef FUNCTIONS_CONFIG_INCLUDED
#define FUNCTIONS_CONFIG_INCLUDED

#define CONFIG_FNAME "/etc/pam-onelogin/pam_onelogin.yaml"

struct config_opt_str {
  char value[128];
};

struct config_opt_int {
  int value;
};

// Struct for handling curl response data
typedef struct Config {
  struct config_opt_str auto_add_group_to_user;
  struct config_opt_int disable_user_password_verification;
  struct config_opt_int debug;
  struct config_opt_int log_stdout;
  struct config_opt_int log_syslog;
  struct config_opt_str onelogin_client_auth_only_id;
  struct config_opt_str onelogin_client_auth_only_secret;
  struct config_opt_str onelogin_client_read_id;
  struct config_opt_str onelogin_client_read_secret;
  struct config_opt_str onelogin_region;
  struct config_opt_str onelogin_subdomain;
  struct config_opt_str onelogin_user_domain_append;
  struct config_opt_str onelogin_user_roles;
  struct config_opt_int parsed;
  struct config_opt_int trace;
} Config;
extern Config config;

void config_parse_file(const char *fname);
void config_parse_line(char *line, int *user_roles_key);
int config_validate_option(char *key, char *val);
void config_validate_option_value(const char *option, char *value);
int config_is_value_true(char *option);
void config_is_value_length_ok(char *opt, char *str, unsigned int max_length);

#endif
