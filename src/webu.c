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

/*  Large portions of this webu module were obtained from
 *  Motion-Project/motion application that that I (MrDave) wrote.
*/

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>

#include "camxmctl.h"
#include "util.h"
#include "webu.h"


/* Context to pass the parms to functions to start mhd */
struct mhdstart_ctx {
    struct ctx_camctl       *camctl;
    char                    *tls_cert;
    char                    *tls_key;
    struct MHD_OptionItem   *mhd_ops;
    int                     mhd_opt_nbr;
    unsigned int            mhd_flags;
    int                     ipv6;
    struct sockaddr_in      lpbk_ipv4;
    struct sockaddr_in6     lpbk_ipv6;
};

static void webu_context_init(struct ctx_camctl *camctl, struct webui_ctx *webui)
{

    webui->url           = malloc(WEBUI_LEN_URLI);
    webui->uri_cmd       = malloc(WEBUI_LEN_URLI);
    webui->clientip      = malloc(WEBUI_LEN_URLI);
    webui->hostname      = malloc(WEBUI_LEN_PARM);
    webui->auth_denied   = malloc(WEBUI_LEN_RESP);
    webui->auth_opaque   = malloc(WEBUI_LEN_PARM);
    webui->auth_realm    = malloc(WEBUI_LEN_PARM);
    webui->auth_username = NULL;                        /* Buffer to hold the username*/
    webui->auth_password = NULL;                        /* Buffer to hold the password */
    webui->authenticated = FALSE;                       /* boolean for whether we are authenticated*/
    webui->resp_size     = WEBUI_LEN_RESP * 10;         /* The size of the resp_page buffer. */
    webui->resp_used     = 0;                           /* How many bytes used so far in resp_page*/
    webui->resp_page     = malloc(webui->resp_size);    /* The response being constructed */
    webui->post_info     = NULL;
    webui->post_sz       = 0;
    webui->cnct_type     = WEBUI_CNCT_UNKNOWN;
    webui->camctl        = camctl;
    memset(webui->hostname,'\0',WEBUI_LEN_PARM);
    memset(webui->resp_page,'\0',webui->resp_size);

    return;
}

static void webu_context_free_var(char* varin)
{
    if (varin != NULL) {
        free(varin);
    }
    varin = NULL;
}

static void webu_context_free(struct webui_ctx *webui)
{
    int indx;

    webu_context_free_var(webui->hostname);
    webu_context_free_var(webui->url);
    webu_context_free_var(webui->uri_cmd);
    webu_context_free_var(webui->resp_page);
    webu_context_free_var(webui->auth_username);
    webu_context_free_var(webui->auth_password);
    webu_context_free_var(webui->auth_denied);
    webu_context_free_var(webui->auth_opaque);
    webu_context_free_var(webui->auth_realm);
    webu_context_free_var(webui->clientip);

    for (indx = 0; indx<webui->post_sz; indx++) {
        webu_context_free_var(webui->post_info[indx].key_nm);
        webu_context_free_var(webui->post_info[indx].key_val);
    }
    free(webui->post_info);
    webui->post_info = NULL;

    free(webui);

    return;
}

/*Copy buf to the response buffer*/
void webu_write(struct webui_ctx *webui, const char *buf)
{
    int      resp_len;
    char    *temp_resp;
    size_t   temp_size;

    resp_len = strlen(buf);

    temp_size = webui->resp_size;
    while ((resp_len + webui->resp_used) > temp_size) {
        temp_size = temp_size + (WEBUI_LEN_RESP * 10);
    }

    if (temp_size > webui->resp_size) {
        temp_resp = malloc(webui->resp_size);
        memcpy(temp_resp, webui->resp_page, webui->resp_size);
        free(webui->resp_page);
        webui->resp_page = malloc(temp_size);
        memset(webui->resp_page,'\0',temp_size);
        memcpy(webui->resp_page, temp_resp, webui->resp_size);
        webui->resp_size = temp_size;
        free(temp_resp);
    }

    memcpy(webui->resp_page + webui->resp_used, buf, resp_len);
    webui->resp_used = webui->resp_used + resp_len;

    return;
}

/*Create the bad response page */
static void webu_badreq(struct webui_ctx *webui)
{
    char response[WEBUI_LEN_RESP];

    snprintf(response, sizeof (response),"%s",
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<body>\n"
        "<p>Bad Request</p>\n"
        "<p>The server did not understand your request.</p>\n"
        "</body>\n"
        "</html>\n");
    webu_write(webui, response);

    return;

}


/* Reset the variables to empty strings*/
static void webu_parseurl_reset(struct webui_ctx *webui)
{
    /* Separate function for future expansion */
    memset(webui->uri_cmd,'\0',WEBUI_LEN_PARM);

}

static int webu_parseurl(struct webui_ctx *webui)
{
    int retcd, parm_len;
    char *st_pos;

    /* Parse the sent URI into the commands and parameters
     * so we can check the resulting strings in later functions
     * and determine what action to take.
     * Samples
     * /
     * /config.json
     *
     * We currently only process / and /config.json so the parsing
     * is currently pretty simple
     */

    webu_parseurl_reset(webui);
    webui->cnct_type = WEBUI_CNCT_CONTROL;

    parm_len = strlen(webui->url);
    if (parm_len == 0) {
        retcd = -1;
    } else {
        MHD_http_unescape(webui->url);
        /* Home page */
        if (parm_len == 1) {
            retcd = 0;
        } else {
            st_pos = webui->url + 1; /* Move past the first "/" */
            parm_len = strlen(webui->url);
            snprintf(webui->uri_cmd, parm_len,"%s", st_pos);
            if (mystreq(webui->uri_cmd,"config.json")) {
                webui->cnct_type = WEBUI_CNCT_JSON;
            }
            retcd = 0;
        }
    }

    //printf("Full url sent: %s Parsed command: %s \n", webui->url, webui->uri_cmd);

    return retcd;

}

/* Extract ip of connecting client */
static void webu_clientip(struct webui_ctx *webui)
{
    const union MHD_ConnectionInfo *con_info;
    char client[WEBUI_LEN_URLI];
    const char *ip_dst;
    struct sockaddr_in6 *con_socket6;
    struct sockaddr_in *con_socket4;
    int is_ipv6;

    is_ipv6 = TRUE;

    con_info = MHD_get_connection_info(webui->connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (is_ipv6) {
        con_socket6 = (struct sockaddr_in6 *)con_info->client_addr;
        ip_dst = inet_ntop(AF_INET6, &con_socket6->sin6_addr, client, WEBUI_LEN_URLI);
        if (ip_dst == NULL) {
            snprintf(webui->clientip, WEBUI_LEN_URLI, "%s", "Unknown");
        } else {
            if (strncmp(client,"::ffff:",7) == 0) {
                snprintf(webui->clientip, WEBUI_LEN_URLI, "%s", client + 7);
            } else {
                snprintf(webui->clientip, WEBUI_LEN_URLI, "%s", client);
            }
        }
    } else {
        con_socket4 = (struct sockaddr_in *)con_info->client_addr;
        ip_dst = inet_ntop(AF_INET, &con_socket4->sin_addr, client, WEBUI_LEN_URLI);
        if (ip_dst == NULL) {
            snprintf(webui->clientip, WEBUI_LEN_URLI, "%s", "Unknown");
        } else {
            snprintf(webui->clientip,WEBUI_LEN_URLI,"%s",client);
        }
    }

}

/* Get hostname from the http header*/
static void webu_hostname(struct webui_ctx *webui)
{
    const char *hdr;
    char *en_pos;
    int host_len;

    hdr = MHD_lookup_connection_value (webui->connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_HOST);
    if (hdr != NULL) {
        snprintf(webui->hostname, WEBUI_LEN_PARM, "%s", hdr);
        /* IPv6 addresses have :'s in them so special case them */
        if (webui->hostname[0] == '[') {
            en_pos = strstr(webui->hostname, "]");
            if (en_pos != NULL) {
                host_len = en_pos - webui->hostname + 2;
                snprintf(webui->hostname, host_len, "%s", hdr);
            }
        } else {
            en_pos = strstr(webui->hostname, ":");
            if (en_pos != NULL) {
                host_len = en_pos - webui->hostname + 1;
                snprintf(webui->hostname, host_len, "%s", hdr);
            }
        }
    } else {
        gethostname(webui->hostname, WEBUI_LEN_PARM - 1);
    }

    /* Assign the type of protocol that is associated with the host
     * so we can use this protocol as we are building the pages
     */
    if (webui->camctl->webcontrol_tls) {
        snprintf(webui->hostproto,6,"%s","https");
    } else {
        snprintf(webui->hostproto,6,"%s","http");
    }

    return;
}

/* Create a denied response to user*/
static mymhd_retcd webu_mhd_digest_fail(struct webui_ctx *webui,int signal_stale)
{
    struct MHD_Response *response;
    mymhd_retcd retcd;

    webui->authenticated = FALSE;

    response = MHD_create_response_from_buffer(strlen(webui->auth_denied)
        ,(void *)webui->auth_denied, MHD_RESPMEM_PERSISTENT);

    if (response == NULL) {
        return MHD_NO;
    }

    retcd = MHD_queue_auth_fail_response(webui->connection, webui->auth_realm
        ,webui->auth_opaque, response
        ,(signal_stale == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO);

    MHD_destroy_response(response);

    return retcd;
}

/* Perform the digest authentication. */
static mymhd_retcd webu_mhd_digest(struct webui_ctx *webui)
{
    int retcd;
    char *username;

    /*Get username or prompt for a username/password */
    username = MHD_digest_auth_get_username(webui->connection);
    if (username == NULL) {
        return webu_mhd_digest_fail(webui, MHD_NO);
    }

    /* Check for valid username name */
    if (mystrne(username, webui->auth_username)) {
        printf("Failed authentication from %s", webui->clientip);
        if (username != NULL) {
            free(username);
        }
        return webu_mhd_digest_fail(webui, MHD_NO);
    }
    if (username != NULL) {
        free(username);
    }

    /* Check the password as well*/
    retcd = MHD_digest_auth_check(webui->connection, webui->auth_realm
        , webui->auth_username, webui->auth_password, 300);

    if (retcd == MHD_NO) {
        printf("Failed authentication from %s", webui->clientip);
    }

    if ( (retcd == MHD_INVALID_NONCE) || (retcd == MHD_NO) )  {
        return webu_mhd_digest_fail(webui, retcd);
    }

    webui->authenticated = TRUE;
    return MHD_YES;

}

/* Create a denied response to user*/
static mymhd_retcd webu_mhd_basic_fail(struct webui_ctx *webui)
{
    struct MHD_Response *response;
    int retcd;

    webui->authenticated = FALSE;

    response = MHD_create_response_from_buffer(strlen(webui->auth_denied)
        ,(void *)webui->auth_denied, MHD_RESPMEM_PERSISTENT);

    if (response == NULL) {
        return MHD_NO;
    }

    retcd = MHD_queue_basic_auth_fail_response (webui->connection, webui->auth_realm, response);

    MHD_destroy_response(response);

    if (retcd == MHD_YES) {
        return MHD_YES;
    } else {
        return MHD_NO;
    }

}

/* Perform Basic Authentication.  */
static mymhd_retcd webu_mhd_basic(struct webui_ctx *webui)
{
    char *username, *password;

    password = NULL;
    username = NULL;

    username = MHD_basic_auth_get_username_password (webui->connection, &password);
    if ((username == NULL) || (password == NULL)) {
        if (username != NULL) {
            free(username);
        }
        if (password != NULL) {
            free(password);
        }
        return webu_mhd_basic_fail(webui);
    }

    if (mystrne(username, webui->auth_username) ||
        mystrne(password, webui->auth_password)) {
        printf("Failed authentication from %s", webui->clientip);
        if (username != NULL) {
            free(username);
        }
        if (password != NULL) {
            free(password);
        }
        return webu_mhd_basic_fail(webui);
    }

    if (username != NULL) {
        free(username);
    }
    if (password != NULL) {
        free(password);
    }

    webui->authenticated = TRUE;
    return MHD_YES;

}

/* Parse apart the username:password provided*/
static void webu_mhd_auth_parse(struct webui_ctx *webui)
{
    int auth_len;
    char *col_pos;

    if (webui->auth_username != NULL) {
        free(webui->auth_username);
    }
    if (webui->auth_password != NULL) {
        free(webui->auth_password);
    }
    webui->auth_username = NULL;
    webui->auth_password = NULL;

    auth_len = strlen(webui->camctl->webcontrol_authentication);
    col_pos = strstr(webui->camctl->webcontrol_authentication,":");
    if (col_pos == NULL) {
        webui->auth_username = malloc(auth_len+1);
        webui->auth_password = malloc(2);
        snprintf(webui->auth_username, auth_len + 1, "%s"
            ,webui->camctl->webcontrol_authentication);
        snprintf(webui->auth_password, 2, "%s","");
    } else {
        webui->auth_username = malloc(auth_len - strlen(col_pos) + 1);
        webui->auth_password = malloc(strlen(col_pos));
        snprintf(webui->auth_username, auth_len - strlen(col_pos) + 1, "%s"
            ,webui->camctl->webcontrol_authentication);
        snprintf(webui->auth_password, strlen(col_pos), "%s", col_pos + 1);
    }

}

/* Set up for authentication functions */
static mymhd_retcd webu_mhd_auth(struct webui_ctx *webui)
{
   unsigned int rand1,rand2;

    snprintf(webui->auth_denied, WEBUI_LEN_RESP, "%s"
        ,"<html><head><title>Access denied</title>"
        "</head><body>Access denied</body></html>");

    srand(time(NULL));
    rand1 = (unsigned int)(42000000.0 * rand() / (RAND_MAX + 1.0));
    rand2 = (unsigned int)(42000000.0 * rand() / (RAND_MAX + 1.0));
    snprintf(webui->auth_opaque, WEBUI_LEN_PARM, "%08x%08x", rand1, rand2);

    snprintf(webui->auth_realm, WEBUI_LEN_PARM, "%s","camxmctl");

    /* Authentication for the webcontrol*/
    if (webui->camctl->webcontrol_authentication == NULL) {
        webui->authenticated = TRUE;
        if (webui->camctl->webcontrol_auth_method != 0) {
            printf("No webcontrol username:password provided");
        }
        return MHD_YES;
    }

    if (webui->auth_username == NULL) {
        webu_mhd_auth_parse(webui);
    }

    if (webui->camctl->webcontrol_auth_method == 1) {
        return webu_mhd_basic(webui);
    } else if (webui->camctl->webcontrol_auth_method == 2) {
        return webu_mhd_digest(webui);
    }

    webui->authenticated = TRUE;
    return MHD_YES;

}

static mymhd_retcd webu_mhd_send(struct webui_ctx *webui)
{
    mymhd_retcd retcd;
    struct MHD_Response *response;

    response = MHD_create_response_from_buffer (strlen(webui->resp_page)
        ,(void *)webui->resp_page, MHD_RESPMEM_PERSISTENT);
    if (!response) {
        printf("Invalid response\n");
        return MHD_NO;
    }

    if (webui->cnct_type == WEBUI_CNCT_JSON) {
        MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
    } else {
        MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");
    }

    retcd = MHD_queue_response (webui->connection, MHD_HTTP_OK, response);

    MHD_destroy_response (response);

    return retcd;
}

static void webu_load_html(struct webui_ctx *webui)
{
    char response[PATH_MAX];
    FILE *fp = NULL;

    fp = fopen(webui->camctl->webcontrol_html, "r");

    if (fp == NULL) {
        printf("Invalid user html file: %s\n"
            , webui->camctl->webcontrol_html);
        webu_badreq(webui);
        return;
    }

    while (fgets(response, PATH_MAX-1, fp)) {
        webu_write(webui, response);
    }
    fclose(fp);

}

static void webu_load_json(struct webui_ctx *webui)
{
    char response[PATH_MAX];
    int indx;

    snprintf(response, 1024,
        "{\"CameraIP\"    : \"%s\" "
        ",\"Username\"    : \"%s\" "
        ",\"Password\"    : \"%s\" "
        ,webui->camctl->cameraip
        ,webui->camctl->username
        ,webui->camctl->password
        );
    webu_write(webui, response);

    for (indx = 0; indx < webui->camctl->cam_info_size; indx++) {
        snprintf(response, 1024,
            ",\"%s\"    : %s "
            ,webui->camctl->cam_info[indx].key_nm
            ,webui->camctl->cam_info[indx].key_val
            );
        webu_write(webui, response);
    }

    snprintf(response, 1024,"%s", "}");
    webu_write(webui, response);

}

static mymhd_retcd webu_answer_get(struct webui_ctx *webui)
{
    mymhd_retcd retcd;

    if (strlen(webui->url) == 0) {
        webu_badreq(webui);
        retcd = webu_mhd_send(webui);
        return retcd;
    }

    if (webui->camctl->webcontrol_finish) {
        return MHD_NO;
    }

    if (strlen(webui->clientip) == 0) {
        webu_clientip(webui);
    }

    webu_hostname(webui);

    if (!webui->authenticated) {
        retcd = webu_mhd_auth(webui);
        if (!webui->authenticated) {
            return retcd;
        }
    }

    if (mystreq(webui->uri_cmd,"config.json")) {
        webu_load_json(webui);
    } else {
        webu_load_html(webui);
    }

    retcd = webu_mhd_send(webui);
    if (retcd == MHD_NO) {
        printf("send page failed \n");
    }

    return retcd;
}

static mymhd_retcd webu_answer_post(struct webui_ctx *webui)
{
    mymhd_retcd retcd;
    int indx, retcd2;

    /* TODO:  Handle more commands sent from the web page such as
     * changing password, PTZ, update parameters, etc
    */

    if (webui->post_cmd == 1) {
        for (indx = 0; indx < webui->post_sz; indx++) {
            if (mystreq(webui->post_info[indx].key_nm, "Username")) {
                webui->camctl->username = calloc(webui->post_info[indx].key_sz+1, sizeof(char));
                retcd2 = snprintf(webui->camctl->username, webui->post_info[indx].key_sz+1, "%s"
                    , webui->post_info[indx].key_val);
                if (retcd2 < 0 ) {
                    printf("Error setting username \n");
                }
            }
            if (mystreq(webui->post_info[indx].key_nm, "Password")) {
                webui->camctl->password = calloc(webui->post_info[indx].key_sz+1, sizeof(char));
                retcd2 = snprintf(webui->camctl->password, webui->post_info[indx].key_sz+1, "%s"
                    , webui->post_info[indx].key_val);
                if (retcd2 < 0 ) {
                    printf("Error setting password \n");
                }
            }
            if (mystreq(webui->post_info[indx].key_nm, "CameraIP")) {
                webui->camctl->cameraip = calloc(webui->post_info[indx].key_sz+1, sizeof(char));
                retcd2 = snprintf(webui->camctl->cameraip, webui->post_info[indx].key_sz+1, "%s"
                    , webui->post_info[indx].key_val);
                if (retcd2 < 0 ) {
                    printf("Error setting camera ip \n");
                }
            }
            /*
            printf("key: %s  value: %s  size: %ld \n"
                , webui->post_info[indx].key_nm
                , webui->post_info[indx].key_val
                , webui->post_info[indx].key_sz
                );
            */
        }
        retcd2 = camctl_login(webui->camctl);
        if (retcd2 == 0) {
            camctl_load(webui->camctl);
        }
    }

    webu_load_html(webui);

    retcd = webu_mhd_send(webui);
    if (retcd == MHD_NO) {
        printf("send post page failed \n");
    }

    return MHD_YES;

}

/*Append more data on to an existing entry in the post info structure */
static void webu_iterate_post_append(struct webui_ctx *webui, int indx
        , const char *data, size_t datasz)
{

    webui->post_info[indx].key_val = realloc(
        webui->post_info[indx].key_val
        , webui->post_info[indx].key_sz + datasz + 1);

    memset(webui->post_info[indx].key_val +
        webui->post_info[indx].key_sz, 0, datasz + 1);

    if (datasz > 0) {
        memcpy(webui->post_info[indx].key_val +
            webui->post_info[indx].key_sz, data, datasz);
    }

    webui->post_info[indx].key_sz += datasz;

}

/*Create new entry in the post info structure */
static void webu_iterate_post_new(struct webui_ctx *webui, const char *key
        , const char *data, size_t datasz)
{
    int retcd;

    webui->post_sz++;
    if (webui->post_sz == 1) {
        webui->post_info = malloc(sizeof(struct ctx_key));
    } else {
        webui->post_info = realloc(webui->post_info, webui->post_sz * sizeof(struct ctx_key));
    }

    webui->post_info[webui->post_sz-1].key_nm = malloc(strlen(key)+1);
    retcd = snprintf(webui->post_info[webui->post_sz-1].key_nm, strlen(key)+1, "%s", key);

    webui->post_info[webui->post_sz-1].key_val = malloc(datasz+1);
    memset(webui->post_info[webui->post_sz-1].key_val,0,datasz+1);
    if (datasz > 0) {
        memcpy(webui->post_info[webui->post_sz-1].key_val, data, datasz);
    }

    webui->post_info[webui->post_sz-1].key_sz = datasz;

    if (retcd < 0) {
        printf("Error processing post data\n");
    }

}

static mymhd_retcd webu_iterate_post (void *ptr, enum MHD_ValueKind kind
        , const char *key, const char *filename, const char *content_type
        , const char *transfer_encoding, const char *data, uint64_t off, size_t datasz)
{
    struct webui_ctx *webui = ptr;
    (void) kind;               /* Unused. Silent compiler warning. */
    (void) filename;           /* Unused. Silent compiler warning. */
    (void) content_type;       /* Unused. Silent compiler warning. */
    (void) transfer_encoding;  /* Unused. Silent compiler warning. */
    (void) off;                /* Unused. Silent compiler warning. */
    int indx;

    if (mystreq(key, "cmdid")) {
        webui->post_cmd = atoi(data);
    } else if (mystreq(key, "trailer") && (datasz ==0)) {
        return MHD_YES;
    }

    for (indx=0; indx < webui->post_sz; indx++) {
        if (mystreq(webui->post_info[indx].key_nm, key)) {
            break;
        }
    }
    if (indx < webui->post_sz) {
        webu_iterate_post_append(webui, indx, data, datasz);
    } else {
        webu_iterate_post_new(webui, key, data, datasz);
    }

    return MHD_YES;
}

/* Answer the request for the webcontrol.*/
static mymhd_retcd webu_answer(void *cls, struct MHD_Connection *connection
            , const char *url, const char *method, const char *version
            , const char *upload_data, size_t *upload_data_size, void **ptr)
{

    mymhd_retcd retcd;
    struct webui_ctx *webui = *ptr;
    (void)cls;
    (void)url;
    (void)version;
    (void)upload_data;

    webui->connection = connection;

    if (webui->mhd_first) {
        webui->mhd_first = FALSE;
        if (mystreq(method,"POST")) {
            webui->postprocessor = MHD_create_post_processor (webui->connection
                , POSTBUFFERSIZE, webu_iterate_post, (void *)webui);
            if (webui->postprocessor == NULL) {
                return MHD_NO;
            }
            webui->cnct_method = POST;
        } else {
            webui->cnct_method = GET;
        }
        return MHD_YES;
    }


    if (mystreq(method,"POST")) {
        if (*upload_data_size != 0) {
            retcd = MHD_post_process (webui->postprocessor, upload_data, *upload_data_size);
            *upload_data_size = 0;
        } else {
            retcd = webu_answer_post(webui);
        }
    } else {
        retcd = webu_answer_get(webui);
    }

    return retcd;

}

/*Process url before answer function is called */
static void *webu_mhd_init(void *cls, const char *uri, struct MHD_Connection *connection)
{
    struct ctx_camctl   *camctl = cls;
    struct webui_ctx    *webui;
    int retcd;
    (void)connection;

    webui = malloc(sizeof(struct webui_ctx));

    webu_context_init(camctl, webui);
    webui->mhd_first = TRUE;

    snprintf(webui->url,WEBUI_LEN_URLI,"%s",uri);

    retcd = webu_parseurl(webui);
    if (retcd != 0) {
        webu_parseurl_reset(webui);
        memset(webui->url,'\0',WEBUI_LEN_URLI);
    }

    return webui;
}

/* Free our webui variables*/
static void webu_mhd_deinit(void *cls, struct MHD_Connection *connection
            , void **con_cls, enum MHD_RequestTerminationCode toe)
{
    struct webui_ctx *webui = *con_cls;
    (void)connection;
    (void)cls;
    (void)toe;

    if (webui != NULL) {
        if (webui->cnct_method == POST) {
            MHD_destroy_post_processor (webui->postprocessor);
        }
        webu_context_free(webui);
    }
    return;
}

/* Test MHD for basic authentication support */
static void webu_mhd_features_basic(struct mhdstart_ctx *mhdst)
{
    #if MHD_VERSION < 0x00094400
        if (mhdst->camctl->webcontrol_auth_method == 1) {
            mhdst->camctl->webcontrol_auth_method = 0;
            printf("Basic authentication:  Disabled. \n");
        } else {
            printf("Basic authentication:  Not available. \n");
        }
    #else
        int retcd;
        retcd = MHD_is_feature_supported (MHD_FEATURE_BASIC_AUTH);
        if (retcd == MHD_YES) {
            printf("Basic authentication:  Available. \n");
        } else {
            if (mhdst->camctl->webcontrol_auth_method == 1) {
                mhdst->camctl->webcontrol_auth_method = 0;
                printf("Basic authentication:  Disabled. \n");
            } else {
                printf("Basic authentication:  Not available. \n");
            }
        }
    #endif
}

/* Test MHD for digest authentication support */
static void webu_mhd_features_digest(struct mhdstart_ctx *mhdst)
{
    #if MHD_VERSION < 0x00094400
        if (mhdst->camctl->webcontrol_auth_method == 2) {
            mhdst->camctl->webcontrol_auth_method = 0;
            printf("Digest authentication:  Disabled. \n");
        } else {
            printf("Digest authentication:  Not available. \n");
        }
    #else
        int retcd;
        retcd = MHD_is_feature_supported (MHD_FEATURE_DIGEST_AUTH);
        if (retcd == MHD_YES) {
            printf("Digest authentication:  Available. \n");
        } else {
            if (mhdst->camctl->webcontrol_auth_method == 2) {
                mhdst->camctl->webcontrol_auth_method = 0;
                printf("Digest authentication:  Disabled. \n");
            } else {
                printf("Digest authentication:  Not available. \n");
            }
        }
    #endif
}

/*Test MHD for ipv6 support */
static void webu_mhd_features_ipv6(struct mhdstart_ctx *mhdst)
{
    #if MHD_VERSION < 0x00094400
        printf("IPV6:  Disabled. \n");
        mhdst->camctl->webcontrol_ipv6 = FALSE;
    #else
        int retcd;
        retcd = MHD_is_feature_supported (MHD_FEATURE_IPv6);
        if (retcd == MHD_YES) {
            printf("IPV6:  Available. \n");
        } else {
            printf("IPV6:  Disabled. \n");
            mhdst->camctl->webcontrol_ipv6 = FALSE;
        }
    #endif
}

/* Test MHD for tls support */
static void webu_mhd_features_tls(struct mhdstart_ctx *mhdst)
{
    #if MHD_VERSION < 0x00094400
        printf("SSL/TLS: disabled \n");
        mhdst->camctl->webcontrol_tls = FALSE;
    #else
        int retcd;
        retcd = MHD_is_feature_supported (MHD_FEATURE_SSL);
        if (retcd == MHD_YES) {
            printf("SSL/TLS: available \n");
        } else {
            printf("SSL/TLS: disabled \n");
            mhdst->camctl->webcontrol_tls = FALSE;
        }
    #endif
}

/* Test MHD for various features */
static void webu_mhd_features(struct mhdstart_ctx *mhdst)
{
    webu_mhd_features_basic(mhdst);

    webu_mhd_features_digest(mhdst);

    webu_mhd_features_ipv6(mhdst);

    webu_mhd_features_tls(mhdst);

}

/* Load the key/cert files for MHD */
static char *webu_mhd_loadfile(const char *fname)
{
    FILE *infile;
    size_t file_size, read_size;
    char * file_char;

    if (fname == NULL) {
        file_char = NULL;
    } else {
        infile = fopen(fname, "rb");
        if (infile != NULL) {
            fseek(infile, 0, SEEK_END);
            file_size = ftell(infile);
            if (file_size > 0 ) {
                file_char = malloc(file_size +1);
                fseek(infile, 0, SEEK_SET);
                read_size = fread(file_char, file_size, 1, infile);
                if (read_size > 0 ) {
                    file_char[file_size] = 0;
                } else {
                    free(file_char);
                    file_char = NULL;
                    printf("\n Error reading file for TLS support. \n");
              }
            } else {
                file_char = NULL;
            }
            fclose(infile);
        } else {
            file_char = NULL;
        }
    }
    return file_char;
}

/*Validate tls information */
static void webu_mhd_checktls(struct mhdstart_ctx *mhdst)
{
    if (mhdst->camctl->webcontrol_tls) {
        if ((mhdst->camctl->webcontrol_cert == NULL) || (mhdst->tls_cert == NULL)) {
            printf("\n TLS requested but no cert file provided.  TLS disabled \n");
            mhdst->camctl->webcontrol_tls = FALSE;
        }
        if ((mhdst->camctl->webcontrol_key == NULL) || (mhdst->tls_key == NULL)) {
            printf("\n TLS requested but no key file provided.  TLS disabled \n");
            mhdst->camctl->webcontrol_tls = FALSE;
        }
    }

}

/*Set the init function for MHD */
static void webu_mhd_opts_init(struct mhdstart_ctx *mhdst)
{
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_URI_LOG_CALLBACK;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = (intptr_t)webu_mhd_init;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = mhdst->camctl;
    mhdst->mhd_opt_nbr++;

}

/* Set the MHD option on the function to call when the connection closes */
static void webu_mhd_opts_deinit(struct mhdstart_ctx *mhdst)
{
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_NOTIFY_COMPLETED;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = (intptr_t)webu_mhd_deinit;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = NULL;
    mhdst->mhd_opt_nbr++;

}

/* Set the MHD option on restricting to localhost */
static void webu_mhd_opts_localhost(struct mhdstart_ctx *mhdst)
{
    if (mhdst->camctl->webcontrol_localhost) {
        if (mhdst->ipv6) {
            memset(&mhdst->lpbk_ipv6, 0, sizeof(struct sockaddr_in6));
            mhdst->lpbk_ipv6.sin6_family = AF_INET6;
            mhdst->lpbk_ipv6.sin6_port = htons(mhdst->camctl->webcontrol_port);
            mhdst->lpbk_ipv6.sin6_addr = in6addr_loopback;

            mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_SOCK_ADDR;
            mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
            mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = (struct sosockaddr *)(&mhdst->lpbk_ipv6);
            mhdst->mhd_opt_nbr++;

        } else {
            memset(&mhdst->lpbk_ipv4, 0, sizeof(struct sockaddr_in));
            mhdst->lpbk_ipv4.sin_family = AF_INET;
            mhdst->lpbk_ipv4.sin_port = htons(mhdst->camctl->webcontrol_port);
            mhdst->lpbk_ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

            mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_SOCK_ADDR;
            mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
            mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = (struct sockaddr *)(&mhdst->lpbk_ipv4);
            mhdst->mhd_opt_nbr++;
        }
    }

}

/* Set the MHD option digest authentication */
static void webu_mhd_opts_digest(struct mhdstart_ctx *mhdst)
{
    if (mhdst->camctl->webcontrol_auth_method== 2) {
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_DIGEST_AUTH_RANDOM;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = sizeof(mhdst->camctl->webcontrol_digest_rand);
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = mhdst->camctl->webcontrol_digest_rand;
        mhdst->mhd_opt_nbr++;

        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_NONCE_NC_SIZE;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 300;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = NULL;
        mhdst->mhd_opt_nbr++;

        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_CONNECTION_TIMEOUT;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = (unsigned int) 120;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = NULL;
        mhdst->mhd_opt_nbr++;
    }

}

/* Set the MHD options needed when we want TLS connections */
static void webu_mhd_opts_tls(struct mhdstart_ctx *mhdst)
{
    if (mhdst->camctl->webcontrol_tls) {
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_HTTPS_MEM_CERT;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = mhdst->tls_cert;
        mhdst->mhd_opt_nbr++;

        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_HTTPS_MEM_KEY;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = mhdst->tls_key;
        mhdst->mhd_opt_nbr++;
    }

}

/* Set all the options we need based upon the parameters*/
static void webu_mhd_opts(struct mhdstart_ctx *mhdst)
{
    mhdst->mhd_opt_nbr = 0;

    webu_mhd_checktls(mhdst);

    webu_mhd_opts_deinit(mhdst);

    webu_mhd_opts_init(mhdst);

    webu_mhd_opts_localhost(mhdst);

    webu_mhd_opts_digest(mhdst);

    webu_mhd_opts_tls(mhdst);

    mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_END;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = NULL;
    mhdst->mhd_opt_nbr++;

}

/* Set the MHD startup flags */
static void webu_mhd_flags(struct mhdstart_ctx *mhdst)
{
    mhdst->mhd_flags = MHD_USE_THREAD_PER_CONNECTION;

    if (mhdst->ipv6) {
        mhdst->mhd_flags = mhdst->mhd_flags | MHD_USE_DUAL_STACK;
    }

    if (mhdst->camctl->webcontrol_tls) {
        mhdst->mhd_flags = mhdst->mhd_flags | MHD_USE_SSL;
    }

}

void webu_stop(struct ctx_camctl *camctl)
{
    if (camctl->webcontrol_daemon != NULL) {
        MHD_stop_daemon (camctl->webcontrol_daemon);
    }
    camctl->webcontrol_daemon = NULL;
}

/* Start mhd */
void webu_start(struct ctx_camctl *camctl)
{
    struct sigaction act;
    struct mhdstart_ctx mhdst;
    unsigned int randnbr;

    /* set signal handlers to IGNORE to allow mhd to function. */
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);
    sigaction(SIGCHLD, &act, NULL);

    camctl->webcontrol_daemon = NULL;

    mhdst.tls_cert = webu_mhd_loadfile(camctl->webcontrol_cert);
    mhdst.tls_key  = webu_mhd_loadfile(camctl->webcontrol_key);
    mhdst.camctl = camctl;
    mhdst.ipv6 = camctl->webcontrol_ipv6;

    /* Set the rand number for webcontrol digest if needed */
    srand(time(NULL));
    randnbr = (unsigned int)(42000000.0 * rand() / (RAND_MAX + 1.0));
    snprintf(camctl->webcontrol_digest_rand
        ,sizeof(camctl->webcontrol_digest_rand),"%d",randnbr);

    camctl->webcontrol_daemon = NULL;

    mhdst.mhd_ops = malloc(sizeof(struct MHD_OptionItem)*WEBUI_MHD_OPTS);

    webu_mhd_features(&mhdst);
    webu_mhd_opts(&mhdst);
    webu_mhd_flags(&mhdst);

    camctl->webcontrol_daemon = MHD_start_daemon (
        mhdst.mhd_flags
        ,camctl->webcontrol_port
        ,NULL, NULL
        ,&webu_answer, camctl
        ,MHD_OPTION_ARRAY, mhdst.mhd_ops
        ,MHD_OPTION_END);
    free(mhdst.mhd_ops);
    if (camctl->webcontrol_daemon == NULL) {
        printf("\n Unable to start MHD \n");
    } else {
        printf("Started webcontrol on port %d \n"
            ,camctl->webcontrol_port);
    }

    if (mhdst.tls_cert != NULL) {
        free(mhdst.tls_cert);
    }
    if (mhdst.tls_key  != NULL) {
        free(mhdst.tls_key);
    }

    return;

}


