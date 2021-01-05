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
#include "webu.h"

static void signal_handler(int signo)
{

    switch(signo) {
    case SIGALRM:
        fprintf(stderr, "Caught alarm signal.\n");
        break;
    case SIGINT:
        fprintf(stderr, "Caught interrupt signal.\n");
        finish = 1;
        break;
    case SIGABRT:
        fprintf(stderr, "Caught abort signal.\n");
        break;
    case SIGHUP:
        fprintf(stderr, "Caught hup signal.\n");
        break;
    case SIGQUIT:
        fprintf(stderr, "Caught quit signal.\n");
        break;
    case SIGIO:
        fprintf(stderr, "Caught IO signal.\n");
        break;
    case SIGTERM:
        fprintf(stderr, "Caught term signal.\n");
        break;
    case SIGPIPE:
        //fprintf(stderr, "Caught pipe signal.\n");
        break;
    case SIGVTALRM:
        fprintf(stderr, "Caught alarm signal.\n");
        break;

    }
}

static void signal_setup(void)
{

    if (signal(SIGPIPE, signal_handler) == SIG_ERR)  fprintf(stderr, "Can not catch pipe signal.\n");
    if (signal(SIGALRM, signal_handler) == SIG_ERR)  fprintf(stderr, "Can not catch alarm signal.\n");
    if (signal(SIGTERM, signal_handler) == SIG_ERR)  fprintf(stderr, "Can not catch term signal.\n");
    if (signal(SIGQUIT, signal_handler) == SIG_ERR)  fprintf(stderr, "Can not catch quit signal.\n");
    if (signal(SIGHUP, signal_handler) == SIG_ERR)  fprintf(stderr, "Can not catch hup signal.\n");
    if (signal(SIGABRT, signal_handler) == SIG_ERR)  fprintf(stderr, "Can not catch abort signal.\n");
    if (signal(SIGVTALRM, signal_handler) == SIG_ERR)  fprintf(stderr, "Can not catch VTalarm\n");
    if (signal(SIGINT, signal_handler) == SIG_ERR)  fprintf(stderr, "Can not catch VTalarm\n");

}

static int camctl_opensocket(struct ctx_camctl *camctl)
{
    int retcd;
    struct sockaddr_in cam_addr;
    struct timeval timeout;

    if (camctl->cameraip == NULL) {
        printf("\n NULL camera IP provided. \n");
        return -1;
    }

    camctl->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (camctl->sockfd < 0)  {
        printf("\n Socket creation error \n");
        return -1;
    }

    cam_addr.sin_family = AF_INET;
    cam_addr.sin_port = htons(camctl->port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    retcd = inet_pton(AF_INET, camctl->cameraip, &cam_addr.sin_addr);
    if(retcd <=0 ) {
        printf("\nInvalid address \n");
        return -1;
    }
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    retcd = setsockopt(camctl->sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    if (retcd < 0 ) {
        printf("\nError setting timeout rcv %d \n", retcd);
        return -1;
    }

    retcd = setsockopt(camctl->sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
    if (retcd < 0 ) {
        printf("\nError setting timeout snd %d\n", retcd);
        return -1;
    }

    retcd = connect(camctl->sockfd, (struct sockaddr *)&cam_addr, sizeof(cam_addr));
    if (retcd < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    return 0;
}

static void prepare_message (struct ctx_msgsend *msgsend, char *msg)
{
    int msglen;

    msglen = strlen(msg) + 1;   /*Extra byte for the null terminator */

    memset(msgsend->buffer, 0, sizeof(msgsend->buffer));

    memcpy(msgsend->buffer, "\xff\x00\x00\x00", 4);
    memcpy(msgsend->buffer + 4, &msgsend->sid, 4);
    memcpy(msgsend->buffer + 8,"\x00\x00\x00\x00", 4);
    memcpy(msgsend->buffer + 14, &msgsend->msg_id, 2);
    memcpy(msgsend->buffer + 16, &msglen, 4);
    memcpy(msgsend->buffer + 20, msg, msglen);

    msgsend->msg_size = msglen + 20;

}

static void prepare_md5(struct ctx_camctl *camctl)
{
    MD5_CTX mdctx;
    int indx;
    unsigned char digest[16];
    char onebyte;

    memset(camctl->hash, 0, sizeof(camctl->hash));

    MD5_Init(&mdctx);
    MD5_Update(&mdctx, camctl->password, strlen(camctl->password));
    MD5_Final(digest, &mdctx);

    /* Adapted from https://github.com/667bdrm/sofiactl */
    for (indx = 0 ; indx < 8 ; indx++ ) {
        onebyte = (digest[ (indx * 2) ] + digest[ (indx *2) + 1 ] ) % 0x3e;
        if (onebyte < 10) {
            onebyte += 48;
        } else if (onebyte < 36) {
            onebyte += 55;
        } else {
            onebyte += 61;
        }
        camctl->hash[indx] = onebyte;
    }

}

int camctl_login(struct ctx_camctl *camctl)
{
    struct ctx_msgsend  msgsend;
    struct ctx_msgresp  resp;
    ssize_t bytes_sent, bytes_read;
    char buffer_out[1024] = {0};
    char buffer_in[1024] = {0};
    int     retcd;

    if ((camctl->password == NULL) ||
        (camctl->username == NULL) ||
        (camctl->cameraip == NULL)) {
        printf("Invalid username/password/cameraip.\n");
        return -1;
    }

    /*
    printf("cameraip: %s  username: %s  password: %s \n"
        ,camctl->cameraip, camctl->username, camctl->password);
    */

    retcd = camctl_opensocket(camctl);
    if (retcd < 0) {
        printf("Error opening socket to camera.\n");
        return -1;
    }

    prepare_md5(camctl);

    snprintf(buffer_in, 1024
        ,"{\"LoginType\"   : \"camxmctl\" "
         ",\"PassWord\"    : \"%s\" "
         ",\"UserName\"    : \"%s\" "
         ",\"EncryptType\" : \"MD5\" }"
         , camctl->hash
         , camctl->username);

    msgsend.msg_id = LOGIN_REQ2;
    msgsend.sid = camctl->sid;
    prepare_message(&msgsend, buffer_in);

    /* TODO:  This needs to loop to ensure we read the entire message */
    bytes_sent = send(camctl->sockfd, msgsend.buffer, msgsend.msg_size, 0 );
    bytes_read = read(camctl->sockfd, buffer_out, 1024);
    if (bytes_read >= 20) {
        memcpy(&resp, buffer_out, sizeof(struct ctx_msgresp));
        printf("bytes read =%ld\n", bytes_read);
        printf(" head=%d version=%d sid=%d seq=%d channel=%d endflag=%d msgid=%d msgsz=%d\n"
            , resp.msg_head
            , resp.msg_version
            , resp.msg_sid
            , resp.msg_seq
            , resp.msg_channel
            , resp.msg_endflag
            , resp.msg_id
            , resp.msg_size
            );
        printf("%s", buffer_out + 20);
        camctl->sid = resp.msg_sid;
        camctl->seq = resp.msg_seq;

        return 0;
    } else {
        printf("Read from socket failed on login.  bytes_sent=%ld bytes_read=%ld\n"
            , bytes_sent, bytes_read);
        return -1;
    }

    return 0;
}

static void config_export(struct ctx_camctl *camctl)
{

    /* This routine is not complete/tested */
    return;

    struct ctx_msgsend  msgsend;
    struct ctx_msgresp  resp;
    ssize_t sbytes;
    char buffer_in[1024] = {0};
    char buffer_out[1024] = {0};

    snprintf(buffer_in, 1024,"{\"Name\": \"\", } ");

    msgsend.msg_id = CONFIG_EXPORT_REQ;
    prepare_message(&msgsend, buffer_in);

    printf(" command bytes=%d %s\n", msgsend.msg_size, buffer_in);
    sbytes = send(camctl->sockfd, msgsend.buffer, msgsend.msg_size, 0 );
    printf(" command sbytes sent =%ld\n", sbytes);

    sbytes = read(camctl->sockfd, buffer_out, 1024);
    if (sbytes >= 20) {
        printf(" command sbytes read =%ld\n", sbytes);
        memcpy(&resp, buffer_out, sizeof(struct ctx_msgresp));
        printf(" head=%d version=%d sid=%d seq=%d channel=%d endflag=%d msgid=%d msgsz=%d\n"
            , resp.msg_head
            , resp.msg_version
            , resp.msg_sid
            , resp.msg_seq
            , resp.msg_channel
            , resp.msg_endflag
            , resp.msg_id
            , resp.msg_size
            );
        /* This function returns a zip file.   Need to continue to read from the socket and write it
         * to a file somewhere so that it can be opened externally to this application
         */
    } else {
        printf(" read from socket failed =%ld\n", sbytes);
    }

}

/* Append the option to our list */
static void camctl_opts_append(struct ctx_camctl *camctl, char *key_nm
        , struct json_object *jobj_val)
{
    int indx, retcd;
    json_type jval_type;

    indx = camctl->cam_info_size;
    if (indx == 0) {
        camctl->cam_info = malloc(sizeof(struct ctx_key));
    } else {
        camctl->cam_info = realloc(camctl->cam_info
            , (indx+1) * sizeof(struct ctx_key));
    }
    camctl->cam_info[indx].key_nm = calloc(strlen(key_nm)+1, sizeof(char));
    retcd = snprintf(camctl->cam_info[indx].key_nm, strlen(key_nm)+1, "%s", key_nm);
    if (retcd < 0) {
        printf("Error extracting the info \n");
    }

    jval_type = json_object_get_type(jobj_val);
    if (jval_type == json_type_string) {
        camctl->cam_info[indx].key_sz = json_object_get_string_len(jobj_val) + 2;
        camctl->cam_info[indx].key_val = calloc(camctl->cam_info[indx].key_sz + 1, sizeof(char));
        retcd = snprintf(camctl->cam_info[indx].key_val
            , camctl->cam_info[indx].key_sz + 1, "\"%s\""
            , json_object_get_string(jobj_val));
    } else if (jval_type == json_type_boolean) {
        camctl->cam_info[indx].key_sz = 5;
        camctl->cam_info[indx].key_val = calloc(camctl->cam_info[indx].key_sz + 1, sizeof(char));
        if (json_object_get_boolean(jobj_val) == TRUE) {
            retcd = snprintf(camctl->cam_info[indx].key_val
                , camctl->cam_info[indx].key_sz + 1, "%s", "true");
        } else {
            retcd = snprintf(camctl->cam_info[indx].key_val
                , camctl->cam_info[indx].key_sz + 1, "%s", "false");
        }
    } else if (jval_type == json_type_int) {
        camctl->cam_info[indx].key_sz = 256;
        camctl->cam_info[indx].key_val = calloc(camctl->cam_info[indx].key_sz + 1, sizeof(char));
        retcd = snprintf(camctl->cam_info[indx].key_val
                , camctl->cam_info[indx].key_sz + 1, "%d"
                , json_object_get_int(jobj_val));
    } else {
        camctl->cam_info[indx].key_sz = strlen(json_type_to_name(jval_type)) + 2;
        camctl->cam_info[indx].key_val = calloc(camctl->cam_info[indx].key_sz + 1, sizeof(char));
        retcd = snprintf(camctl->cam_info[indx].key_val
            , camctl->cam_info[indx].key_sz + 1, "\"%s\""
            , json_type_to_name(jval_type));

    }
    if (retcd < 0) {
        printf("Error appending the info \n");
    }
    camctl->cam_info_size++;

}

/* Iterate through the json objects */
static void camctl_opts_iterate(struct ctx_camctl *camctl
        , const char *key, const char *rslt, int debug)
{
    struct json_object *jobj_src, *jobj_val;
    struct json_object_iterator jobj_it, jobj_end;
    char *tmpname;
    int name_sz, retcd;

    jobj_src = json_tokener_parse(rslt);
    jobj_it = json_object_iter_begin(jobj_src);
    jobj_end = json_object_iter_end(jobj_src);

    if (debug) {
        printf("json:\n---\n%s\n---\n\n",
            json_object_to_json_string_ext(jobj_src, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    }

    while (json_object_iter_equal(&jobj_it, &jobj_end) == FALSE ) {
        jobj_val = json_object_iter_peek_value(&jobj_it);

        if (mystreq(key, json_object_iter_peek_name(&jobj_it))) {
            name_sz = strlen(key) + 1;
            tmpname = malloc(name_sz);
            retcd = snprintf(tmpname, name_sz, "%s",key);
        } else {
            name_sz = strlen(json_object_iter_peek_name(&jobj_it)) + strlen(key) + 2;
            tmpname = malloc(name_sz);
            retcd = snprintf(tmpname, name_sz, "%s.%s", key, json_object_iter_peek_name(&jobj_it));
        }
        if (retcd < 0) {
            printf("Error settting up json name.\n");
        }

        if (json_object_get_type(jobj_val) == json_type_object) {
            camctl_opts_iterate(camctl
                , tmpname
                , json_object_to_json_string_ext(jobj_val,JSON_C_TO_STRING_SPACED)
                , debug);
        } else {
            camctl_opts_append(camctl, tmpname, json_object_iter_peek_value(&jobj_it));
            if (debug) {
                printf("%s %s\n"
                    , camctl->cam_info[camctl->cam_info_size-1].key_nm
                    , camctl->cam_info[camctl->cam_info_size-1].key_val);
            }
        }

        free(tmpname);
        json_object_iter_next(&jobj_it);
    }
}

/* Get camera configuration options and values */
static void camctl_opts_get(struct ctx_camctl *camctl, const char *opt
        , int msgid, int debug)
{
    struct ctx_msgsend  msgsend;
    struct ctx_msgresp  resp;
    ssize_t bytes_read, bytes_sent, bufloc;
    char buffer_in[1024] = {0};
    char buffer_out[2048] = {0};
    char *fullbuff;
    int counter;

    snprintf(buffer_in, 1024
        , "{\"Name\": \"%s\" ,\"SessionID\" : \"0x%08x\"}"
        , opt, camctl->sid);

    msgsend.msg_id = msgid;
    prepare_message(&msgsend, buffer_in);

    bytes_read = 0;
    counter = 0;
    bytes_sent = send(camctl->sockfd, msgsend.buffer, msgsend.msg_size, 0 );
    while ((bytes_read == 0) && (counter < 10)) {
        SLEEP(0, 200000000L);
        bytes_read = read(camctl->sockfd, buffer_out, 2048);
        counter++;
    }

    if (bytes_read >= 20) {
        memcpy(&resp, buffer_out, sizeof(struct ctx_msgresp));

        bufloc = bytes_read - 20;
        fullbuff = malloc(resp.msg_size);
        memcpy(fullbuff, buffer_out + 20, bufloc);

        if (bufloc < resp.msg_size) {
            while (bufloc < resp.msg_size) {
                bytes_read = read(camctl->sockfd, buffer_out, 2048);
                if (bytes_read > 0) {
                    memcpy(fullbuff+bufloc, buffer_out, bytes_read);
                    bufloc += bytes_read;
                } else {
                    bufloc = resp.msg_size;
                }
            }
        }
        camctl_opts_iterate(camctl, opt, fullbuff, debug);
        free(fullbuff);
    } else {
        printf("Read from socket failed. bytes_sent %ld bytes_read: %ld\n"
            , bytes_sent, bytes_read);
    }
}

void camctl_load(struct ctx_camctl *camctl)
{
    /* TODO:  Review and add more calls here to get additional
     * information from the camera...users, etc
     */
    camctl_opts_get(camctl,"Ability.SerialNo.SerialNo", CONFIG_GET, FALSE);
    camctl_opts_get(camctl,"SystemInfo", SYSINFO_REQ, FALSE);
    camctl_opts_get(camctl,"NetWork", CONFIG_GET, TRUE);

    /*
    camctl_opts_get(camctl,"Ability", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"Alarm", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"AVEnc", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"Camera", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"Detect", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"fVideo", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"General", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"Guide", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"NetWork", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"OEMcfg", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"Produce", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"Record", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"SplitMode", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"Storage", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"System", CONFIG_GET, TRUE);
    camctl_opts_get(camctl,"Uart", CONFIG_GET, TRUE);
    */

}

static void camctl_parms(struct ctx_camctl *camctl)
{
    int slen;

    /* TODO:  These need to be read in from a config file */
    camctl->webcontrol_auth_method = 0;
    camctl->webcontrol_authentication = NULL;
    camctl->webcontrol_cert = NULL;
    camctl->webcontrol_daemon = NULL;
    camctl->webcontrol_finish = FALSE;
    camctl->webcontrol_ipv6 = FALSE;
    camctl->webcontrol_key = NULL;
    camctl->webcontrol_localhost = FALSE;
    camctl->webcontrol_port = 7985;
    camctl->webcontrol_tls = FALSE;
    camctl->cam_info = NULL;
    camctl->username = NULL;
    camctl->password = NULL;
    camctl->cameraip = NULL;
    camctl->port =  34567;

    slen= strlen("./data/camctl.html");
    camctl->webcontrol_html = malloc(slen+10);
    snprintf(camctl->webcontrol_html, slen+2, "%s",
        "./data/camctl.html");
}

int main(int argc, char **argv)
{
    int   retcd;
    struct ctx_camctl *camctl;
    (void)argc;
    (void)argv;

    retcd = 0;
    finish = 0;

    camctl = malloc(sizeof(struct ctx_camctl));
    memset(camctl, 0, sizeof(struct ctx_camctl));

    signal_setup();

    camctl_parms(camctl);

    webu_start(camctl);

    while (finish == FALSE) {
        SLEEP(1,0);
    }
    webu_stop(camctl);

    close(camctl->sockfd);

    return retcd;

    /* This is just a place holder until this functionality gets built*/
    config_export(camctl);

}


