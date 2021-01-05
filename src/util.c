/*   This file is part of camxmctl.
 *
 *   camxmctl is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   camxmctl is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with camxmctl.  If not, see <https://www.gnu.org/licenses/>.
 */


#include "camxmctl.h"
#include "util.h"

    /* List obtained from https://github.com/667bdrm/sofiactl */
struct ctx_camretcd cam_retcds[] = {
    {100 , "OK"},
    {101 , "unknown mistake"},
    {102 , "Version not supported"},
    {103 , "Illegal request"},
    {104 , "The user has logged in"},
    {105 , "The user is not logged in"},
    {106 , "username or password is wrong"},
    {107 , "No permission"},
    {108 , "time out"},
    {109 , "Failed to find no corresponding file found"},
    {110 , "Find successful, return all files"},
    {111 , "Find success, return some files"},
    {112 , "This user already exists"},
    {113 , "this user does not exist"},
    {114 , "This user group already exists"},
    {115 , "This user group does not exist"},
    {116 , "Error 116"},
    {117 , "Wrong message format"},
    {118 , "PTZ protocol not set"},
    {119 , "No query to file"},
    {120 , "Configure to enable"},
    {121 , "MEDIA_CHN_NOT CONNECT digital channel is not connected"},
    {150 , "Successful, the device needs to be restarted"},
    {202 , "User not logged in"},
    {203 , "The password is incorrect"},
    {204 , "User illegal"},
    {205 , "User is locked"},
    {206 , "User is on the blacklist"},
    {207 , "Username is already logged in"},
    {208 , "Input is illegal"},
    {209 , "The index is repeated if the user to be added already exists, etc."},
    {210 , "No object exists, used when querying"},
    {211 , "Object does not exist"},
    {212 , "Account is in use"},
    {213 , "The subset is out of scope (such as the group's permissions exceed the permission table, the user permissions exceed the group permission range, etc."},
    {214 , "The password is illegal"},
    {215 , "Passwords do not match"},
    {216 , "Retain account"},
    {502 , "The command is illegal"},
    {503 , "Intercom has been turned on"},
    {504 , "Intercom is not turned on"},
    {511 , "Already started upgrading"},
    {512 , "Not starting upgrade"},
    {513 , "Upgrade data error"},
    {514 , "upgrade unsuccessful"},
    {515 , "update successed"},
    {521 , "Restore default failed"},
    {522 , "Need to restart the device"},
    {523 , "Illegal default configuration"},
    {602 , "Need to restart the app"},
    {603 , "Need to restart the system"},
    {604 , "Error writing a file"},
    {605 , "Feature not supported"},
    {606 , "verification failed"},
    {607 , "Configuration does not exist"},
    {608 , "Configuration parsing error"},
    {-999, NULL}
};

/** Non case sensitive equality check for strings*/
int mystrceq(const char *var1, const char *var2)
{
    if ((var1 == NULL) || (var2 == NULL)) {
        return FALSE;
    }
    return (strcasecmp(var1,var2) ? FALSE : TRUE);
}

/** Non case sensitive inequality check for strings*/
int mystrcne(const char *var1, const char *var2)
{
    if ((var1 == NULL) || (var2 == NULL)) {
        return FALSE;
    }
    return (strcasecmp(var1,var2) ? TRUE : FALSE);
}

/** Case sensitive equality check for strings*/
int mystreq(const char *var1, const char *var2)
{
    if ((var1 == NULL) || (var2 == NULL)) {
        return FALSE;
    }
    return (strcmp(var1,var2) ? FALSE : TRUE);
}

/** Case sensitive inequality check for strings*/
int mystrne(const char *var1, const char *var2)
{
    if ((var1 == NULL) ||(var2 == NULL)) {
        return FALSE;
    }
    return (strcmp(var1,var2) ? TRUE : FALSE);
}

/* Trim away any leading or trailing whitespace in string */
void util_trim(char *parm)
{
    int indx, indx_st, indx_en;

    if (parm == NULL) {
        return;
    }

    indx_en = strlen(parm) - 1;
    if (indx_en == -1) {
        return;
    }

    indx_st = 0;

    while (isspace(parm[indx_st]) && (indx_st <= indx_en)) {
        indx_st++;
    }
    if (indx_st > indx_en) {
        parm[0]= '\0';
        return;
    }

    while (isspace(parm[indx_en]) && (indx_en > indx_st)) {
        indx_en--;
    }

    for (indx = indx_st; indx<=indx_en; indx++) {
        parm[indx-indx_st] = parm[indx];
    }
    parm[indx_en-indx_st+1] = '\0';

}

