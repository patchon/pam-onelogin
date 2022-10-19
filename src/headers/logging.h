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

#ifndef FUNCTIONS_HEADERS_INCLUDED
#define FUNCTIONS_HEADERS_INCLUDED
#include <stdarg.h>

void perr(char *str, ...);
void pinf(char *str, ...);
void pwrn(char *str, ...);
void ptrc(char *str, ...);
void pfnc(const char *str);

char *timestamp(void);
int calculate_buf_length(const char *str, va_list argp_copy);
#endif
