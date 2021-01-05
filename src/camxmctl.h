#ifndef _INCLUDE_CAMXMCTL_H_
#define _INCLUDE_CAMXMCTL_H_

    #include <pthread.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <ctype.h>
    #include <dirent.h>
    #include <errno.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <signal.h>
    #include <sys/time.h>
    #include <time.h>
    #include <openssl/md5.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <string.h>
    #include <json-c/json.h>
    #include <openssl/md5.h>
    #include <microhttpd.h>


    #define SLEEP(seconds, nanoseconds) {              \
                    struct timespec tv;                \
                    tv.tv_sec = (seconds);             \
                    tv.tv_nsec = (nanoseconds);        \
                    while (nanosleep(&tv, &tv) == -1); \
            }

    struct ctx_msgsend {
        char        prefix00[4];
        int         sid;
        char        prefix01[4];
        short int   msg_id;
        int         msg_size;
        char        buffer[1024];
    };

    struct ctx_msgresp {
        char        msg_head;
        char        msg_version;
        char        msg_reserved00;
        char        msg_reserved01;
        int         msg_sid;
        int         msg_seq;
        char        msg_channel;
        char        msg_endflag;
        short int   msg_id;
        int         msg_size;
    };

    struct ctx_camctl {
        int                 sockfd;
        int                 head_flag;
        int                 version;
        int                 sid;
        int                 seq;
        char                *cameraip;
        char                *username;
        char                *password;
        char                hash[9];
        int                 port;
        struct ctx_key      *cam_info;
        int                 cam_info_size;
        struct MHD_Daemon   *webcontrol_daemon;
        char                *webcontrol_cert;
        char                *webcontrol_key;
        int                 webcontrol_ipv6;
        char                webcontrol_digest_rand[8];
        int                 webcontrol_port;
        int                 webcontrol_tls;
        int                 webcontrol_auth_method;
        int                 webcontrol_localhost;
        int                 webcontrol_finish;
        char                *webcontrol_authentication;
        char                *webcontrol_html;
    };


    volatile int finish;  /* Stop the application */

    struct ctx_camretcd {
        int         retcd_nbr;        /* Return code number */
        const char  *retcd_desc;      /* Description of the return code */
    };

    struct ctx_key {
        char    *key_nm;        /* Name of the key item */
        char    *key_val;       /* Value of the key item */
        size_t  key_sz;         /* The size of the value */
    };

    int camctl_login(struct ctx_camctl *camctl);
    void camctl_load(struct ctx_camctl *camctl);

#endif