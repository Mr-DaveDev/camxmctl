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

#ifndef _INCLUDE_UTIL_H
#define _INCLUDE_UTIL_H

    /* List obtained from https://github.com/667bdrm/sofiactl */

    #define LOGIN_REQ1                      999
    #define LOGIN_REQ2                      1000
    #define LOGIN_RSP                       1000
    #define LOGOUT_REQ                      1001
    #define LOGOUT_RSP                      1002
    #define FORCELOGOUT_REQ                 1003
    #define FORCELOGOUT_RSP                 1004
    #define KEEPALIVE_REQ                   1006    //??# 1005??
    #define KEEPALIVE_RSP                   1007    //??# 1006??

    #define SYSINFO_REQ                     1020
    #define SYSINFO_RSP                     1021

    #define CONFIG_SET                      1040
    #define CONFIG_SET_RSP                  1041
    #define CONFIG_GET                      1042
    #define CONFIG_GET_RSP                  1043
    #define DEFAULT_CONFIG_GET              1044
    #define DEFAULT_CONFIG_GET_RSP          1045
    #define CONFIG_CHANNELTILE_SET          1046
    #define CONFIG_CHANNELTILE_SET_RSP      1047
    #define CONFIG_CHANNELTILE_GET          1048
    #define CONFIG_CHANNELTILE_GET_RSP      1049
    #define CONFIG_CHANNELTILE_DOT_SET      1050
    #define CONFIG_CHANNELTILE_DOT_SET_RSP  1051

    #define SYSTEM_DEBUG_REQ                1052
    #define SYSTEM_DEBUG_RSP                1053

    #define ABILITY_GET                     1360
    #define ABILITY_GET_RSP                 1361

    #define PTZ_REQ                         1400
    #define PTZ_RSP                         1401

    #define MONITOR_REQ                     1410
    #define MONITOR_RSP                     1411
    #define MONITOR_DATA                    1412
    #define MONITOR_CLAIM                   1413
    #define MONITOR_CLAIM_RSP               1414

    #define PLAY_REQ                        1420
    #define PLAY_RSP                        1421
    #define PLAY_DATA                       1422
    #define PLAY_EOF                        1423
    #define PLAY_CLAIM                      1424
    #define PLAY_CLAIM_RSP                  1425
    #define DOWNLOAD_DATA                   1426

    #define TALK_REQ                        1430
    #define TALK_RSP                        1431
    #define TALK_CU_PU_DATA                 1432
    #define TALK_PU_CU_DATA                 1433
    #define TALK_CLAIM                      1434
    #define TALK_CLAIM_RSP                  1435

    #define FILESEARCH_REQ                  1440
    #define FILESEARCH_RSP                  1441
    #define LOGSEARCH_REQ                   1442
    #define LOGSEARCH_RSP                   1443
    #define FILESEARCH_BYTIME_REQ           1444
    #define FILESEARCH_BYTIME_RSP           1445

    #define SYSMANAGER_REQ                  1450
    #define SYSMANAGER_RSP                  1451
    #define TIMEQUERY_REQ                   1452
    #define TIMEQUERY_RSP                   1453

    #define DISKMANAGER_REQ                 1460
    #define DISKMANAGER_RSP                 1461

    #define FULLAUTHORITYLIST_GET           1470
    #define FULLAUTHORITYLIST_GET_RSP       1471
    #define USERS_GET                       1472
    #define USERS_GET_RSP                   1473
    #define GROUPS_GET                      1474
    #define GROUPS_GET_RSP                  1475
    #define ADDGROUP_REQ                    1476
    #define ADDGROUP_RSP                    1477
    #define MODIFYGROUP_REQ                 1478
    #define MODIFYGROUP_RSP                 1479
    #define DELETEGROUP_REQ                 1480
    #define DELETEGROUP_RSP                 1481
    #define ADDUSER_REQ                     1482
    #define ADDUSER_RSP                     1483
    #define MODIFYUSER_REQ                  1484
    #define MODIFYUSER_RSP                  1485
    #define DELETEUSER_REQ                  1486
    #define DELETEUSER_RSP                  1487
    #define MODIFYPASSWORD_REQ              1488
    #define MODIFYPASSWORD_RSP              1489

    #define GUARD_REQ                       1500
    #define GUARD_RSP                       1501
    #define UNGUARD_REQ                     1502
    #define UNGUARD_RSP                     1503
    #define ALARM_REQ                       1504
    #define ALARM_RSP                       1505
    #define NET_ALARM_REQ                   1506
    #define NET_ALARM_REQ2                  1507
    #define ALARMCENTER_MSG_REQ             1508

    #define UPGRADE_REQ                     1520
    #define UPGRADE_RSP                     1521
    #define UPGRADE_DATA                    1522
    #define UPGRADE_DATA_RSP                1523
    #define UPGRADE_PROGRESS                1524
    #define UPGRADE_INFO_REQ                1525
    #define UPGRADE_INFO_RSQ                1526

    #define IPSEARCH_REQ                    1530
    #define IPSEARCH_RSP                    1531
    #define IP_SET_REQ                      1532
    #define IP_SET_RSP                      1533

    #define CONFIG_IMPORT_REQ               1540
    #define CONFIG_IMPORT_RSP               1541
    #define CONFIG_EXPORT_REQ               1542
    #define CONFIG_EXPORT_RSP               1543
    #define LOG_EXPORT_REQ                  1544    //?? #CONDIG_EXPORT_REQ ??
    #define LOG_EXPORT_RSP                  1545    //?? #CONFIG_EXPORT_RSP ??

    #define NET_KEYBOARD_REQ                1550
    #define NET_KEYBOARD_RSP                1551

    #define NET_SNAP_REQ                    1560
    #define NET_SNAP_RSP                    1561
    #define SET_IFRAME_REQ                  1562
    #define SET_IFRAME_RSP                  1563

    #define RS232_READ_REQ                  1570
    #define RS232_READ_RSP                  1571
    #define RS232_WRITE_REQ                 1572
    #define RS232_WRITE_RSP                 1573
    #define RS485_READ_REQ                  1574
    #define RS485_READ_RSP                  1575
    #define RS485_WRITE_REQ                 1576
    #define RS485_WRITE_RSP                 1577
    #define TRANSPARENT_COMM_REQ            1578
    #define TRANSPARENT_COMM_RSP            1579
    #define RS485_TRANSPARENT_DATA_REQ      1580
    #define RS485_TRANSPARENT_DATA_RSP      1581
    #define RS232_TRANSPARENT_DATA_REQ      1582
    #define RS232_TRANSPARENT_DATA_RSP      1583

    #define SYNC_TIME_REQ                   1590
    #define SYNC_TIME_RSP                   1591

    #define PHOTO_GET_REQ                   1600
    #define PHOTO_GET_RSP                   1601

#ifndef TRUE
    #define TRUE 1
#endif

#ifndef FALSE
    #define FALSE 0
#endif

#if MHD_VERSION >= 0x00097002
    typedef enum MHD_Result mymhd_retcd;
#else
    typedef int mymhd_retcd;
#endif


int mystrceq(const char *var1, const char *var2);
int mystrcne(const char *var1, const char *var2);
int mystreq(const char *var1, const char *var2);
int mystrne(const char *var1, const char *var2);
void util_trim(char *parm);

#endif