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

#ifndef _INCLUDE_WEBU_H_
#define _INCLUDE_WEBU_H_


/* Some defines of lengths for our buffers */
#define WEBUI_LEN_PARM 512          /* Parameters specified */
#define WEBUI_LEN_URLI 512          /* Maximum URL permitted */
#define WEBUI_LEN_RESP 1024         /* Initial response size */
#define WEBUI_MHD_OPTS 10           /* Maximum number of options permitted for MHD */
#define WEBUI_LEN_LNK  15           /* Maximum length for chars in strminfo */
#define GET             0
#define POST            1
#define POSTBUFFERSIZE  512

enum WEBUI_CNCT{
  WEBUI_CNCT_CONTROL     = 0,
  WEBUI_CNCT_JSON        = 1,
  WEBUI_CNCT_UNKNOWN     = 99
};

struct webui_ctx {
    char *url;                  /* The URL sent from the client */
    char *uri_cmd;              /* Parsed command from the url*/

    char *hostname;             /* Host name provided from header content*/
    char  hostproto[6];         /* Protocol for host http or https */
    char *clientip;             /* IP of the connecting client */
    char *auth_denied;          /* Denied access response to user*/
    char *auth_opaque;          /* Opaque string for digest authentication*/
    char *auth_realm;           /* Realm string for digest authentication*/
    char *auth_username;        /* Parsed username from config authentication string*/
    char *auth_password;        /* Parsed password from config authentication string*/
    int  authenticated;         /* Boolean for whether authentication has been passed */
    enum WEBUI_CNCT             cnct_type;  /* Type of connection we are processing */

    int                     post_sz;      /* The number of entries in the post info */
    int                     post_cmd;     /* The command sent with the post */
    struct ctx_key          *post_info;   /* Structure of the entries provided from the post data */

    char                    *resp_page;   /* The response that will be sent */
    size_t                  resp_size;    /* The allocated size of the response */
    size_t                  resp_used;    /* The amount of the response page used */
    uint64_t                stream_pos;   /* Stream position of sent image */
    int                     stream_fps;   /* Stream rate per second */
    struct timeval          time_last;    /* Keep track of processing time for stream thread*/

    int                         mhd_first;      /* Boolean for whether it is the first connection*/
    struct ctx_camctl           *camctl;        /* Main camera control structure of application */
    struct MHD_Connection       *connection;    /* The MHD connection value from the client */
    int                         cnct_method;    /* Connection method.  Get or Post */
    struct MHD_PostProcessor    *postprocessor; /* Processor for handling Post method connections */
};

void webu_start(struct ctx_camctl *camctl);
void webu_stop(struct ctx_camctl *camctl);
void webu_process_action(struct webui_ctx *webui);
int webu_process_config(struct webui_ctx *webui);
int webu_process_track(struct webui_ctx *webui);
void webu_write(struct webui_ctx *webui, const char *buf);

#endif
