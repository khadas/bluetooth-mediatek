/**
 * This software/firmware and related documentation ("MediaTek Software") are
 * protected under relevant copyright laws. The information contained herein is
 * confidential and proprietary to MediaTek Inc. and/or its licensors. Without
 * the prior written permission of MediaTek inc. and/or its licensors, any
 * reproduction, modification, use or disclosure of MediaTek Software, and
 * information contained herein, in whole or in part, shall be strictly
 * prohibited.
 *
 * MediaTek Inc. (C) 2016. All rights reserved.
 *
 * BY OPENING THIS FILE, RECEIVER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND AGREES
 * THAT THE SOFTWARE/FIRMWARE AND ITS DOCUMENTATIONS ("MEDIATEK SOFTWARE")
 * RECEIVED FROM MEDIATEK AND/OR ITS REPRESENTATIVES ARE PROVIDED TO RECEIVER
 * ON AN "AS-IS" BASIS ONLY. MEDIATEK EXPRESSLY DISCLAIMS ANY AND ALL
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR
 * NONINFRINGEMENT. NEITHER DOES MEDIATEK PROVIDE ANY WARRANTY WHATSOEVER WITH
 * RESPECT TO THE SOFTWARE OF ANY THIRD PARTY WHICH MAY BE USED BY,
 * INCORPORATED IN, OR SUPPLIED WITH THE MEDIATEK SOFTWARE, AND RECEIVER AGREES
 * TO LOOK ONLY TO SUCH THIRD PARTY FOR ANY WARRANTY CLAIM RELATING THERETO.
 * RECEIVER EXPRESSLY ACKNOWLEDGES THAT IT IS RECEIVER'S SOLE RESPONSIBILITY TO
 * OBTAIN FROM ANY THIRD PARTY ALL PROPER LICENSES CONTAINED IN MEDIATEK
 * SOFTWARE. MEDIATEK SHALL ALSO NOT BE RESPONSIBLE FOR ANY MEDIATEK SOFTWARE
 * RELEASES MADE TO RECEIVER'S SPECIFICATION OR TO CONFORM TO A PARTICULAR
 * STANDARD OR OPEN FORUM. RECEIVER'S SOLE AND EXCLUSIVE REMEDY AND MEDIATEK'S
 * ENTIRE AND CUMULATIVE LIABILITY WITH RESPECT TO THE MEDIATEK SOFTWARE
 * RELEASED HEREUNDER WILL BE, AT MEDIATEK'S OPTION, TO REVISE OR REPLACE THE
 * MEDIATEK SOFTWARE AT ISSUE, OR REFUND ANY SOFTWARE LICENSE FEES OR SERVICE
 * CHARGE PAID BY RECEIVER TO MEDIATEK FOR SUCH MEDIATEK SOFTWARE AT ISSUE.
 *
 * The following software/firmware and/or related documentation ("MediaTek
 * Software") have been modified by MediaTek Inc. All revisions are subject to
 * any receiver's applicable license agreements with MediaTek Inc.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "bperf_util.h"

#include "common.h"

#ifdef OS_FRTOS
#include "osi_frtos.h"
extern char *ppicus_optarg;
extern int *ppicus_optind;

#define CLEAN_DRIVER_PICUS_BUFFER()    \
    DBGPRINT(ERROR, "clean driver buffer");    \
    do {    \
        ret = osi_read(fd, buffer, sizeof(buffer));    \
    } while (ret > 0);    \

#define CHECK_READ_LENGTH(ret, length)    \
    if (ret < length) {    \
        DBGPRINT(ERROR, "clean driver buffer");    \
        CLEAN_DRIVER_PICUS_BUFFER()    \
        continue;    \
    }
#define FIRST_PICUS_READ_LEN 3
#else
#include "osi_linux.h"
char *ppicus_optarg;
int *ppicus_optind;
#endif

//---------------------------------------------------------------------------
#define VERSION     "6.0.20071601"
#define LOG_VERSION 0x100
#define FWLOG_DEV   "/dev/stpbtfwlog"

#define HCE_CONNECTION_COMPLETE 0x03
#define HCE_COMMAND_COMPLETE    0x0E
#define HCE_VENDOR_EVENT        0xFF

#define TCI_SYS_LOG_EVENT       0x50    // define in firmware for event
#define TCI_SYS_LOG_ACL         0x05
#define PICUS_EVENT_HDR_LEN     3
#define PICUS_ACL_HDR_LEN       4

#define PICUS_BUF_SIZE          1944    // Cover old BT driver return size

//---------------------------------------------------------------------------
static const uint64_t BTSNOOP_EPOCH_DELTA = 0x00dcddb30f2f8000ULL;
static uint64_t timestamp = 0;
static uint8_t buffer[PICUS_BUF_SIZE] = {0};
static uint8_t cont = 1;    /** loop continue running */
static int file_size_remain_to_switch = 0;
static uint8_t bperf_start = 0;
static int buf_length;
static int buf_size;
static char *buf;

//---------------------------------------------------------------------------
uint64_t btsnoop_timestamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    // Timestamp is in microseconds.
    timestamp = tv.tv_sec * 1000000ULL;
    timestamp += tv.tv_usec;
    timestamp += BTSNOOP_EPOCH_DELTA;
    return timestamp;
}
//---------------------------------------------------------------------------
void fillheader(unsigned char *header, int headerlen,
        unsigned short int dump_file_seq_num)
{
    int copy_hedare_len = 0;
    unsigned int logversion = osi_htobe32(LOG_VERSION);
    memset(header, 0, headerlen);
    memcpy(header, &logversion, sizeof(logversion));
    copy_hedare_len += 4;   /** 4 byte for logversion */
    copy_hedare_len += 4;   /** 4 byte for chip id, not implement yet */
    dump_file_seq_num = osi_htobe16(dump_file_seq_num);
    memcpy(header + copy_hedare_len, &dump_file_seq_num, sizeof(dump_file_seq_num));
    copy_hedare_len += 2;   /** 2 byte for sequence number */
    copy_hedare_len += 6;   /** first hci log length(2), zero(4) */
    btsnoop_timestamp();
    timestamp = osi_htobe64(timestamp);
    memcpy(header + copy_hedare_len, &timestamp, sizeof(timestamp));
}
//---------------------------------------------------------------------------
static void picus_sig_handler(int signum)
{
    DBGPRINT(SHOW, "%s: %d", __func__, signum);
    osi_system("echo 01 be fc 01 00 > "FWLOG_DEV);      // disable picus log
    cont = 0;                                       // stop loop
    if (bperf_start) {
        osi_system("echo bperf=0 > "FWLOG_DEV);         // disable bperf
        bperf_uninit();
    }
    if (buf_size) {
        buf_size = 0;
        free(buf);
    }
}
//---------------------------------------------------------------------------
#ifdef OS_FRTOS
int picus_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    OSI_FILE *fscript = 0;
    OSI_FILE *fw_dump_fscript = 0;
    int nRead = 0;
    int fd = 0;
    int ret = 0;
    int opt;
    int dump_name_index = 0;
    int writetofilelength = 0;
    char dump_file_name[64] = {0};
    int fw_dump_writetofilelength = 0;
    char fw_dump_file_name[64] = {0};
    int retry_file_open = 0;
    int file_number = 6;
    int file_size = FW_LOG_SWITCH_SIZE;     /** default file size is 20 MB */
    char *log_path = DEFAULT_PATH;
    char command[300] = {0};
    unsigned char padding[8] = {0};
    unsigned char header[24] = {0};
    int fw_log_len = 0;
    unsigned short int dump_file_seq_num = 0;
    char timestamp_buffer[24];
    osi_fd_set rset;                            /** For select */
    TIMEVAL tv;
    TIME_T local_timestamp;
    uint8_t logmore = 0;                    /** Default log level */
    SIGACTION sigact;
    FLOCK fl;
    char rssi_per_package = 0;
    char get_afh = 0;
    char picus_fullname[PATH_MAX + NAME_MAX + 2] = {0};
    uint16_t handle = 0;
    /** Debugging Feature : hci-base interaction mode */
    /** Create fifo for inteprocess communication */
    char Dhci_myfifo[100] = {0};
    static int Dhci_fd1 = 0;
    static int Dhci_enable = 0;
    char Dhci_buffer[HCI_MAX_EVENT_SIZE] = {0};
    int Dhci_event_number = 0;
    unsigned short set_bperf = 0;
    uint8_t coredump_end = 0;
    int send_enable_fwlog = 1;
#ifdef OS_FRTOS
    int second_part_len = 0;
    int read_payload_len = 0;
#endif

    if (argv)
        DBGPRINT(SHOW, "%s Version: %s", argv[0], VERSION);
    else
        DBGPRINT(SHOW, "argv is NULL, Version: %s", VERSION);


    init_sigaction(&sigact, picus_sig_handler);
    init_flock(&fl);

#ifdef OS_FRTOS
    DBGPRINT(SHOW, "FRTOS\n");
#else
    DBGPRINT(SHOW, "Linux\n");
    ppicus_optarg = optarg;
    ppicus_optind = &optind;
#endif
    /* Create fifo for hci-base communication */
    snprintf(Dhci_myfifo, sizeof(Dhci_myfifo), HCI_FIFO_PATH);
    if (osi_mkfifo(Dhci_myfifo, 0666) < 0)
        DBGPRINT(ERROR, "create fifo failed(%d)", errno);

    while ((opt = osi_getopt(argc, argv, "t:d:c:p:n:s:b:l:mf")) != -1) {
        /* If your option didn't use argument, please don't use ':' into getopt */
        switch (opt) {
        /* debug */
        case 'd':
            if (strcmp(ppicus_optarg, "kill") == 0) {
                osi_system("echo 01 be fc 01 00 > "FWLOG_DEV);     // disable picus log firstly
                osi_system("killall picus");
                DBGPRINT(SHOW, "Kill all picus process.\n");
                goto done;
            } else if (strcmp(ppicus_optarg, "trigger") == 0) {
                osi_system("echo 01 be fc 01 00 > "FWLOG_DEV);     // disable picus log firstly
                DBGPRINT(SHOW, "Manual Trigger FW Assert.\n");
                osi_system("echo 01 6f fc 05 01 02 01 00 08 > "FWLOG_DEV);
                return 0;
            } else if (strcmp(ppicus_optarg, "rssi") == 0) {
                DBGPRINT(SHOW, "Send read rssi command.\n");
                int i;
                for (i = 0; i < 6; i++) {
                    char command[64] = {0};
                    int default_bredr_handle = 32;
                    /* Send Read RSSI command for bredr, handle is 0x0032 ~ 0x0037 */
                    snprintf(command, sizeof(command), "echo 01 61 FC 02 %d 00 > /dev/stpbtfwlog", default_bredr_handle + i);
                    osi_system(command);
                    osi_usleep(10000);
                    /* Send Read RSSI command for LE, handle is 0x0200 ~ 0x0205 */
                    snprintf(command, sizeof(command), "echo 01 61 FC 02 %02d 02 > /dev/stpbtfwlog", i);
                    osi_system(command);
                    osi_usleep(10000);
                }
                return 0;
            } else if (strcmp(ppicus_optarg, "per") == 0) {
                DBGPRINT(SHOW, "Send read per command.\n");
                osi_system("echo 01 11 FD 00 > "FWLOG_DEV);
                return 0;
            } else if (strcmp(ppicus_optarg, "ble_scan_on") == 0) {
                DBGPRINT(SHOW, "Send ble scan disable command. (Duplicate_Filter:True)");
                osi_system("echo 01 0c 20 02 00 01 > "FWLOG_DEV);
                DBGPRINT(SHOW, "Send APCF delete command.");
                osi_system("echo 01 57 fd 03 01 01 00 > "FWLOG_DEV);
                osi_system("echo 01 57 fd 12 01 00 00 00 00 01 00 00 81 00 00 00 00 00 00 00 00 00 > "FWLOG_DEV);
                DBGPRINT(SHOW, "Send ble set scan parameter command. (5000ms/5000ms)");
                osi_system("echo 01 0b 20 07 01 40 1f 40 1f 01 00 > "FWLOG_DEV);
                DBGPRINT(SHOW, "Send ble scan enable command. (Duplicate_Filter:False)");
                osi_system("echo 01 0c 20 02 01 00 > "FWLOG_DEV);
                return 0;
            } else if (strcmp(ppicus_optarg, "ble_scan_off") == 0) {
                DBGPRINT(SHOW, "Send ble scan disable command. (Duplicate_Filter:True)");
                osi_system("echo 01 0c 20 02 00 01 > "FWLOG_DEV);
                return 0;
            } else if (strcmp(ppicus_optarg, "inquiry") == 0) {
                DBGPRINT(SHOW, "Send inquiry command.");
                osi_system("echo 01 01 04 05 33 8b 9e 0a 00 > "FWLOG_DEV);
                return 0;
            } else if (strcmp(ppicus_optarg, "bperf") == 0) {
                set_bperf = 1;
                DBGPRINT(SHOW, "set set_bperf= %d", set_bperf);
            } else if (strcmp(ppicus_optarg, D_FIFO_DATA) == 0) {
                DBGPRINT(SHOW, "Start Record .\n");
                /* enable Record CMD/ACL/EVT */
                Dhci_enable = 1;
                osi_system("echo bperf=1 > "FWLOG_DEV);
                Dhci_fd1 = osi_open(Dhci_myfifo, OSI_RDWR | OSI_NONBLOCK);
                if (Dhci_fd1 <= 0) {
                    DBGPRINT(ERROR, "Can't open fifo %s, fd: %d", Dhci_myfifo, Dhci_fd1);
                }
            } else if (strcmp(ppicus_optarg, "afh") == 0) {
                get_afh = 1;
                break;
            } else if (strcmp(ppicus_optarg, "en_rssi") == 0) {
                rssi_per_package = 1;
                break;
            } else if (strcmp(ppicus_optarg, "dis_rssi") == 0) {
                rssi_per_package = 2;
                break;
            }
            break;
        /* set bperf test option */
        case 'b':
            DBGPRINT(SHOW, "get set_bperf= %d", set_bperf);
            if (set_bperf) {
                if (strstr(ppicus_optarg, "all") || strstr(ppicus_optarg, "ALL")) {
                    int i = 0;
                    for (i = 0; i <= BPERF_BLE_SCAN; i++)
                        bperf_mem_init(i);
                } else if (strstr(ppicus_optarg, "voice"))
                    bperf_mem_init(BPERF_VOICE);
                else if (strstr(ppicus_optarg, "rc") || strstr(ppicus_optarg, "RC"))
                    bperf_mem_init(BPERF_RC);
                else if (strstr(ppicus_optarg, "hid") || strstr(ppicus_optarg, "HID") )
                    bperf_mem_init(BPERF_HID);
                else if (strstr(ppicus_optarg, "hogp") || strstr(ppicus_optarg, "HOGP") )
                    bperf_mem_init(BPERF_HOGP);
                else if (strstr(ppicus_optarg, "a2dp") || strstr(ppicus_optarg, "A2DP") )
                    bperf_mem_init(BPERF_A2DP);
                else if (strstr(ppicus_optarg, "blescan") || strstr(ppicus_optarg, "BLESCAN") )
                    bperf_mem_init(BPERF_BLE_SCAN);
            }
            break;
        /* set bperf average timer length */
        case 't':
            DBGPRINT(SHOW, "bperf average timer length is set to %d secondsd", atoi(ppicus_optarg));
            bperf_set_average_timer(atoi(ppicus_optarg));
            break;
        /* send command */
        case 'c':
            Dhci_fd1 = osi_open(Dhci_myfifo, OSI_O_WRONLY | OSI_O_NONBLOCK);
            if (Dhci_fd1 <= 0) {
                DBGPRINT(ERROR, "Can't open fifo %s, fd: %d", Dhci_myfifo, Dhci_fd1);
            } else {
                osi_write(Dhci_fd1, D_FIFO_DATA, strlen(D_FIFO_DATA));
                osi_close(Dhci_fd1);
            }
            snprintf(command, sizeof(command), "echo %s > "FWLOG_DEV, ppicus_optarg);
            osi_system(command);
            return 0;
        /* change path */
        case 'p':
            DBGPRINT(SHOW, "-p ppicus_optarg = %s\n", ppicus_optarg);
            if (OSI_STAT(ppicus_optarg)) {
                log_path = ppicus_optarg;
                DBGPRINT(SHOW, "Log path is %s\n", log_path);
            } else {
                DBGPRINT(SHOW, "Directory is invalid");
                goto done;
            }
            break;
        /* change file number*/
        case 'n':
            file_number = atoi(ppicus_optarg);
            DBGPRINT(SHOW, "Change the number of file to %d.\n", file_number);
            break;
        /* change file size*/
        case 's':
            file_size = atoi(ppicus_optarg);
            DBGPRINT(SHOW, "Change the size of file to %d.\n", file_size);
            break;
        /* change buf from driver size*/
        case 'l':
            buf_size = atoi(ppicus_optarg);
            DBGPRINT(SHOW, "Change the size of buf to %d.", buf_size);
            break;
        /* full log */
        case 'f':
            logmore = 1;
            break;
        case 'm':
            send_enable_fwlog = 0;
            break;
        /* command Usage */
        case '?':
        default:
            DBGPRINT(SHOW, "Usage: picus [option] [path | command]");
            DBGPRINT(SHOW, "[option]");
            DBGPRINT(SHOW, "\t-d [command]\tSend debug command");
            DBGPRINT(SHOW, "\t  \t\tUsing \"kill\" command to kill all picus");
            DBGPRINT(SHOW, "\t  \t\tUsing \"trigger\" command to trigger fw assert");
            DBGPRINT(SHOW, "\t  \t\tUsing \"bperf\" command to read Bluetooth KPI data");
            DBGPRINT(SHOW, "\t  \t\tUsing \"inquiry\" command to send inquiry command");
            DBGPRINT(SHOW, "\t  \t\tUsing \"ble_scan_on\" command to enable ble scan");
            DBGPRINT(SHOW, "\t  \t\tUsing \"ble_scan_off\" command to disable ble scan");
            DBGPRINT(SHOW, "\t  \t\tUsing \"rssi\" command to read rssi");
            DBGPRINT(SHOW, "\t  \t\tUsing \"afh\" command to read afh table");
            DBGPRINT(SHOW, "\t  \t\tUsing \"per\" command to read per");
            DBGPRINT(SHOW, "\t  \t\tUsing \"en_rssi\" command to enable read rssi/channel every package");
            DBGPRINT(SHOW, "\t  \t\tUsing \"dis_rssi\" command to disable read rssi/channel every package");
            DBGPRINT(SHOW, "\t-c [command]\tsend command");
            DBGPRINT(SHOW, "\t-p [path]\tOutput the file to specific dictionary");
            DBGPRINT(SHOW, "\t-n [NO]\t\tChange the output file number");
            DBGPRINT(SHOW, "\t-s [bytes]\tChange the output file size");
            DBGPRINT(SHOW, "\t-t [seconds]\tChange the bperf average timer length");
            DBGPRINT(SHOW, "\t-f\t\tLog level: More");
            goto done;
            break;
        }
    }

    if (set_bperf) {
        DBGPRINT(SHOW, "Start bperf.");
        /* enable Record CMD/ACL/EVT */
        osi_system("echo bperf=1 > "FWLOG_DEV);
        bperf_init();
        bperf_start = 1;
    }

    if (rssi_per_package > 0) {
        char command[64] = {0};
        printf("%s", argv[*ppicus_optind]);
        handle = (uint16_t)strtoul(argv[*ppicus_optind], NULL, 16);
        if (rssi_per_package == 1) {
            snprintf(command, sizeof(command), "echo 01 72 FD 03 01 %02X %02X > %s", (uint8_t)(handle & 0x00FF), (uint8_t)((handle & 0xFF00) >> 8), FWLOG_DEV);
            DBGPRINT(SHOW, "Send enable rssi/afh log command.");
            osi_system(command);
        }
        else {
            snprintf(command, sizeof(command), "echo 01 72 FD 03 00 %02X %02X > %s", (uint8_t)(handle & 0x00FF), (uint8_t)((handle & 0xFF00) >> 8), FWLOG_DEV);
            DBGPRINT(SHOW, "Send disable rssi/afh log command.\n");
            osi_system(command);
        }
        return 0;
    }
    if (get_afh > 0) {
        char command[64] = {0};
        handle = (uint16_t)strtoul(argv[*ppicus_optind], NULL, 16);
        snprintf(command, sizeof(command), "echo 01 06 14 02 %02X %02X > %s", (uint8_t)(handle & 0x00FF), (uint8_t)((handle & 0xFF00) >> 8), FWLOG_DEV);
        DBGPRINT(SHOW, "Send get afh command.");
        osi_system(command);
        return 0;
    }

    /* stpbtfwlog */
    int i;
    for (i = 1; i <= RETRY_COUNT; i++) {
        fd = osi_open(CUST_BT_FWLOG_PORT, OSI_RDWR | OSI_NOCTTY | OSI_NONBLOCK);
        if (fd <= 0) {
            DBGPRINT(ERROR, "Can't open device node %s, fd: %d", CUST_BT_FWLOG_PORT, fd);
            osi_usleep(100000);
            if (i == RETRY_COUNT)
                goto done;
            else
                continue;
        } else {
            DBGPRINT(SHOW, "Open device node successfully fd = %d", fd);
            break;
        }
    }

    /* flock the device node */
    if (osi_fcntl(fd, OSI_F_SETLK, &fl) < 0) {
        DBGPRINT(SHOW, "lock device node failed, picus already running.");
        goto done;
    }

    if (buf_size > file_size) {
        buf_size = 0;
        DBGPRINT(SHOW, "buf size larger than file, set defaule value, no buf.");
    } else {
        buf = malloc(buf_size);
        if (buf == NULL) {
            DBGPRINT(ERROR, "Malloc buf file.");
            goto done;
        }
        DBGPRINT(SHOW, " Alloc buf for save fwlog, size is %d.", buf_size);
    }

    /* log level */
    if (send_enable_fwlog) {
        if (logmore)
            ret = osi_system("echo 01 5f fc 2e 50 01 0A 00 00 00 01 00 00 E0 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 01 01 00 01 00 00 00 01 00 00 00 00 00 00 00 > "FWLOG_DEV);    // Log More
        else
            ret = osi_system("echo 01 5f fc 2e 50 01 0A 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 > "FWLOG_DEV);    // Default Level

        if (ret == -1)
            DBGPRINT(ERROR, "Set log level fail");

        /* enable it firstly */
        ret = osi_system("echo 01 be fc 01 15 > "FWLOG_DEV);
        if (ret == -1)
            DBGPRINT(ERROR, "Enable fail");
        DBGPRINT(SHOW, "Log %slevel set and enabled", logmore ? "more " : "");
    }
    osi_usleep(10000);

    /* check already exist file under log_path */
    char temp_picus_zero_filename[36] = {0};
    DIR *p_dir = osi_opendir(log_path);
    if (p_dir != NULL) {
        DIRENT *p_file;
        while ((p_file = osi_readdir(p_dir)) != NULL) {
            /* ignore . and .. directory */
            if (strncmp(osi_get_dirent_name(p_file), "..", 2) == 0
                || strncmp(osi_get_dirent_name(p_file), ".", 1) == 0) {
                continue;
            }
            /* Remove the old picus log */
            if (strstr(osi_get_dirent_name(p_file), DUMP_PICUS_NAME_EXT) != NULL) {
                memset(temp_picus_zero_filename, 0, sizeof(temp_picus_zero_filename));
                snprintf(temp_picus_zero_filename, sizeof(temp_picus_zero_filename), "%s", osi_get_dirent_name(p_file));
                memset(picus_fullname, 0, sizeof(picus_fullname));
                snprintf(picus_fullname, sizeof(picus_fullname), "%s/%s", log_path, temp_picus_zero_filename);
                if (osi_remove(picus_fullname)) {
                    DBGPRINT(SHOW, "The old log:%s can't remove", temp_picus_zero_filename);
                } else {
                    DBGPRINT(SHOW, "The old log:%s remove", temp_picus_zero_filename);
                }
            }
            /* Remove the old fw_dump log */
            if (strstr(osi_get_dirent_name(p_file), FW_DUMP_PICUS_NAME_PREFIX) != NULL) {
                memset(temp_picus_zero_filename, 0, sizeof(temp_picus_zero_filename));
                snprintf(temp_picus_zero_filename, sizeof(temp_picus_zero_filename), "%s", osi_get_dirent_name(p_file));
                memset(picus_fullname, 0, sizeof(picus_fullname));
                snprintf(picus_fullname, sizeof(picus_fullname), "%s/%s", log_path, temp_picus_zero_filename);
                if (osi_remove(picus_fullname)) {
                    DBGPRINT(SHOW, "The old log:%s can't remove", temp_picus_zero_filename);
                } else {
                    DBGPRINT(SHOW, "The old log:%s remove", temp_picus_zero_filename);
                }
            }
        }
        osi_closedir(p_dir);
    }

    /* get current timestamp */
    osi_time(&local_timestamp);
    osi_strftime(timestamp_buffer, 24, "%Y%m%d%H%M%S", osi_localtime(&local_timestamp));
    snprintf(dump_file_name, sizeof(dump_file_name), "%s/" DUMP_PICUS_NAME_PREFIX "%s_%d" DUMP_PICUS_NAME_EXT, log_path, timestamp_buffer, dump_name_index);

    /* dump file for picus log */
    if ((fscript = osi_fopen(dump_file_name, "wb")) == NULL) {
        DBGPRINT(ERROR, "Open script file %s fail [%s] errno %d", dump_file_name, strerror(errno), errno);
        goto done;
    } else {
        DBGPRINT(SHOW, "%s created, dumping...", dump_file_name);
    }

    fillheader(header, sizeof(header), dump_file_seq_num);
    dump_file_seq_num++;
    osi_fwrite(header, 1, sizeof(header), fscript);
    osi_fwrite(padding, 1, sizeof(padding), fscript);

    ret = 0;
    retry_file_open = 0;
    file_size_remain_to_switch = file_size;

    do {
        FD_ZERO(&rset);
        osi_FD_SET(fd,&rset);
        set_timeval(&tv, 10, 0);/* timeout is 10s for select method */
        if (osi_select(fd + 1, &rset, NULL, NULL, &tv) == 0) {
            DBGPRINT(ERROR, "Read data timeout(10s) from stpbtfwlog");
            continue;
        }

        if (!osi_FD_ISSET(fd, &rset))
            continue;
#ifdef OS_FRTOS
        /* Read packet header and length from driver fwlog queue */
        memset(buffer, 0, sizeof(buffer));
        ret = osi_read(fd, buffer, FIRST_PICUS_READ_LEN);

        if (ret <= 0)
            continue;

        nRead = ret;
        CHECK_READ_LENGTH(ret, FIRST_PICUS_READ_LEN);
        switch(buffer[0]) {
            case 0xFF:/*picus data*/
                if (buffer[2] == 0x50)
                    second_part_len = buffer[1] - 1 + PICUS_EVENT_HDR_LEN - FIRST_PICUS_READ_LEN;
                else if (buffer[1] == 0x05)
                    second_part_len = (buffer[3] << 8) + buffer[2] + PICUS_ACL_HDR_LEN - FIRST_PICUS_READ_LEN;
                else {
                    PICUS_RAW_INFO(buffer, nRead, "Read data error");
                    DBGPRINT(DEEPTRACE, "clean driver buffer");
                    do {
                        ret = osi_read(fd, buffer, sizeof(buffer));
                    } while (ret > 0);
                    continue;
                }

                /* Read payload from driver fwlog queue */
                ret = osi_read(fd, &buffer[FIRST_PICUS_READ_LEN], second_part_len);
                nRead += ret;
                CHECK_READ_LENGTH(ret, second_part_len);
                break;
            case DATA_TYPE_COMMAND:
                ret = osi_read(fd, &buffer[FIRST_PICUS_READ_LEN], HCI_COMMAND_TPYE_LENGTH);
                nRead += ret;
                CHECK_READ_LENGTH(ret, HCI_COMMAND_TPYE_LENGTH);
                if (buffer[FIRST_PICUS_READ_LEN]) {
                    ret = osi_read(fd, &buffer[FIRST_PICUS_READ_LEN + HCI_COMMAND_TPYE_LENGTH], buffer[FIRST_PICUS_READ_LEN]);
                    nRead += ret;
                    CHECK_READ_LENGTH(ret, buffer[FIRST_PICUS_READ_LEN]);
                }
                DBGPRINT(DEEPTRACE, "Read DATA_TYPE_COMMAND nRead = %d, buffer[0] = %02x",nRead, buffer[0]);
                break;
            case DATA_TYPE_ACL:
                ret = osi_read(fd, &buffer[FIRST_PICUS_READ_LEN], HCI_ACL_TPYE_LENGTH);
                nRead += ret;
                CHECK_READ_LENGTH(ret, HCI_ACL_TPYE_LENGTH);
                read_payload_len = buffer[FIRST_PICUS_READ_LEN + 1];
                read_payload_len = (read_payload_len<<8) + buffer[FIRST_PICUS_READ_LEN];
                if (read_payload_len) {
                    ret = osi_read(fd, &buffer[FIRST_PICUS_READ_LEN + HCI_ACL_TPYE_LENGTH], read_payload_len);
                    nRead += ret;
                    CHECK_READ_LENGTH(ret, read_payload_len);
                }
                break;

            case DATA_TYPE_EVENT:
                read_payload_len = buffer[FIRST_PICUS_READ_LEN - 1];
                if (read_payload_len) {
                    ret = osi_read(fd, &buffer[FIRST_PICUS_READ_LEN], read_payload_len);
                    nRead += ret;
                    CHECK_READ_LENGTH(ret, read_payload_len);
                }
                break;

            default:
                DBGPRINT(WARN, "buffer[0] may error = 0x%02x", buffer[0]);
                PICUS_RAW_INFO(buffer, nRead, "Read data:");
                CLEAN_DRIVER_PICUS_BUFFER();
                continue;
        }




#else
        /* Read all packet from driver fwlog queue */
        ret = osi_read(fd, buffer, sizeof(buffer));
        nRead = ret;
#endif
        if (Dhci_enable) {
            memset(Dhci_buffer, 0, sizeof(Dhci_buffer));
            if (osi_read(Dhci_fd1, Dhci_buffer, strlen(D_FIFO_DATA)) > 0) {
                DBGPRINT(DEEPTRACE, "Read data from fifo : %s", Dhci_buffer);
                if (strcmp(Dhci_buffer, D_FIFO_DATA) == 0)
                    Dhci_event_number++;
                else
                    DBGPRINT(SHOW, "Read incorrect data from fifo : %s", Dhci_buffer);
            }
        }

        if (nRead >= 3) {
            /* picus log */
            if ((buffer[0] == HCE_VENDOR_EVENT && buffer[2] == TCI_SYS_LOG_EVENT) ||
                (buffer[0] == HCE_VENDOR_EVENT && buffer[1] == TCI_SYS_LOG_ACL)) {
                /* Picus Event format : FF xx 50 */
                /* Picus ACL format : FF 05 xx xx */
                /* xx is length */
                /* process multiple packet from fwlog queue */
                int index = 0;

                while (index + 1 < nRead) {
                    /* Event format for 7662, 7668 */
                    if (buffer[index] == HCE_VENDOR_EVENT && buffer[index + 2] == TCI_SYS_LOG_EVENT) {
                        writetofilelength = buffer[1 + index] - 1;
                        fw_log_len = buffer[1 + index] - 1;
                        if (index + PICUS_EVENT_HDR_LEN + writetofilelength > PICUS_BUF_SIZE) {
                            writetofilelength = PICUS_BUF_SIZE - index - PICUS_EVENT_HDR_LEN;
                            DBGPRINT(WARN, "Event pkt size more than buffer(org:%d, reduced:%d)",
                                    fw_log_len, writetofilelength);
                            fw_log_len = PICUS_BUF_SIZE - index - PICUS_EVENT_HDR_LEN;
                        }

                        if (buf_size == 0) {
                            osi_fwrite(&buffer[PICUS_EVENT_HDR_LEN + index], 1, writetofilelength, fscript);
                        } else {
                            if ((buf_length + writetofilelength) < buf_size) {
                                memcpy(buf + buf_length, &buffer[PICUS_EVENT_HDR_LEN + index], writetofilelength);
                                buf_length += writetofilelength;
                            } else {
                                osi_fwrite(buf, 1, buf_length, fscript);
                                osi_fwrite(&buffer[PICUS_EVENT_HDR_LEN + index], 1, writetofilelength, fscript);
                                buf_length = 0;
                            }
                        }

                    /* ACL format for 7668 and 7663 */
                    } else if (buffer[index] == HCE_VENDOR_EVENT && buffer[index + 1] == TCI_SYS_LOG_ACL) {
                        writetofilelength = (buffer[3 + index] << 8) + buffer[2 + index];
                        fw_log_len = (buffer[3 + index] << 8) + buffer[2 + index];
                        if (index + PICUS_ACL_HDR_LEN + writetofilelength > PICUS_BUF_SIZE) {
                            writetofilelength = PICUS_BUF_SIZE - index - PICUS_ACL_HDR_LEN;
                            DBGPRINT(WARN, "ACL pkt size more than buffer(org:%d, reduced:%d)",
                                    fw_log_len, writetofilelength);
                            fw_log_len = PICUS_BUF_SIZE - index - PICUS_ACL_HDR_LEN;
                        }

                        if (buf_size == 0) {
                            osi_fwrite(&buffer[PICUS_ACL_HDR_LEN + index], 1, writetofilelength, fscript);
                        } else {
                            if ((buf_length + writetofilelength) < buf_size) {
                                memcpy(buf + buf_length, &buffer[PICUS_ACL_HDR_LEN + index], writetofilelength);
                                buf_length += writetofilelength;
                            } else {
                                osi_fwrite(buf, 1, buf_length, fscript);
                                osi_fwrite(&buffer[PICUS_ACL_HDR_LEN + index], 1, writetofilelength, fscript);
                                buf_length = 0;
                            }
                        }

                    }

                    file_size_remain_to_switch -= writetofilelength;

                    if (writetofilelength % 8) {
                        if (buf_size == 0) {
                            osi_fwrite(padding, 1, 8 - (fw_log_len % 8), fscript);
                        } else {
                            if ((buf_length + 8 - (fw_log_len % 8)) < buf_size) {
                                memcpy(buf + buf_length, padding, 8 - (fw_log_len % 8));
                                buf_length += 8 - (fw_log_len % 8);
                            } else {
                                osi_fwrite(buf, 1, buf_length, fscript);
                                osi_fwrite(padding, 1, 8 - (fw_log_len % 8), fscript);
                                buf_length = 0;
                            }
                        }
                        file_size_remain_to_switch -= (8 - (fw_log_len % 8));
                    }

                    /* switch file name if file size is over file_size */
                    if (file_size_remain_to_switch <= 0) {
                        file_size_remain_to_switch = file_size;
                        osi_fclose(fscript);
                        if (file_number - 1 > dump_name_index) {
                            dump_name_index++;
                        } else {
                            dump_name_index = 0;
                        }
                        /* remove the file before creating */
                        DIR *p_dir = osi_opendir(log_path);
                        if (p_dir != NULL) {
                            DIRENT *p_file;
                            while ((p_file = osi_readdir(p_dir)) != NULL) {
                                if (strncmp(osi_get_dirent_name(p_file), "..", 2) == 0
                                    || strncmp(osi_get_dirent_name(p_file), ".", 1) == 0) {
                                    continue;
                                }
                                char temp_picus_filename[24] = {0};
                                snprintf(temp_picus_filename, sizeof(temp_picus_filename), "_%d.picus", dump_name_index);
                                if (strstr(osi_get_dirent_name(p_file), temp_picus_filename) != NULL) {
                                    memset(picus_fullname, 0, sizeof(picus_fullname));
                                    snprintf(picus_fullname, sizeof(picus_fullname), "%s/%s", log_path, osi_get_dirent_name(p_file));
                                    if (osi_remove(picus_fullname)) {
                                        DBGPRINT(SHOW, "%s can't remove", picus_fullname);
                                    } else {
                                        DBGPRINT(SHOW, "%s remove", picus_fullname);
                                    }
                                }
                            }
                            osi_closedir(p_dir);
                        }
                        osi_time(&local_timestamp);
                        osi_strftime(timestamp_buffer, 24, "%Y%m%d%H%M%S", osi_localtime(&local_timestamp));
                        snprintf(dump_file_name, sizeof(dump_file_name), "%s/" DUMP_PICUS_NAME_PREFIX "%s_%d" DUMP_PICUS_NAME_EXT, log_path, timestamp_buffer, dump_name_index);

                        while(1) {
                            if ((fscript = osi_fopen(dump_file_name, "wb")) == NULL) {
                                DBGPRINT(ERROR, "Open script file %s fail [%s] errno %d",
                                        dump_file_name, strerror(errno), errno);
                                if (retry_file_open >= RETRY_COUNT)
                                    goto done;
                            } else {
                                DBGPRINT(SHOW, "%s created, dumping...", dump_file_name);
                                retry_file_open = 0;
                                break;
                            }
                            ++retry_file_open;
                        }

                        fillheader(header, sizeof(header), dump_file_seq_num);
                        dump_file_seq_num++;
                        osi_fwrite(header, 1, sizeof(header), fscript);
                    }
                    osi_fflush(fscript);
                    if (buffer[0] == HCE_VENDOR_EVENT && buffer[2] == TCI_SYS_LOG_EVENT) {
                        /* Add Picus event header len and payload */
                        /* EVENT Header : 3 bytes, payload : 240 bytes */
                        index += PICUS_EVENT_HDR_LEN + fw_log_len;
                    } else if (buffer[0] == HCE_VENDOR_EVENT && buffer[1] == TCI_SYS_LOG_ACL) {
                        /* Add Picus ACL header len and payload */
                        /* ACL Header : 4 bytes, payload : 240 bytes */
                        index += PICUS_ACL_HDR_LEN + fw_log_len;
                    }
                }

            /* coredump */
            } else if (buffer[0] == 0x6F && buffer[1] == 0xFC) {
                /* dump file for fw dump */
                if (fw_dump_fscript == NULL) {
                    osi_time(&local_timestamp);
                    osi_strftime(timestamp_buffer, 24, "%Y%m%d%H%M%S", osi_localtime(&local_timestamp));
                    /* combine file path and file name */
                    snprintf(fw_dump_file_name, sizeof(fw_dump_file_name), "%s/" FW_DUMP_PICUS_NAME_PREFIX "%s", log_path, timestamp_buffer);

                    while(1) {
                        if ((fw_dump_fscript = osi_fopen(fw_dump_file_name, "wb")) == NULL) {
                            DBGPRINT(ERROR, "Open script file %s fail [%s] errno %d", fw_dump_file_name,
                                    strerror(errno), errno);
                            if (retry_file_open >= RETRY_COUNT)
                                goto done;
                        } else {
                            DBGPRINT(SHOW, "%s created, dumping...", fw_dump_file_name);
                            retry_file_open = 0;
                            break;
                        }
                        ++retry_file_open;
                    }
                }
                fw_dump_writetofilelength = nRead - 4;
                if (buffer[nRead - 6] == ' ' &&
                    buffer[nRead - 5] == 'e' &&
                    buffer[nRead - 4] == 'n' &&
                    buffer[nRead - 3] == 'd') {
                    coredump_end = 1;
                    DBGPRINT(SHOW, "FW dump end");
                }
                osi_fwrite(&buffer[4], 1, fw_dump_writetofilelength, fw_dump_fscript);
                osi_fflush(fw_dump_fscript);
                if (coredump_end) {
                    osi_fclose(fw_dump_fscript);
                    fw_dump_fscript = NULL;
                    coredump_end = 0;
                }
            } else if (buffer[4] == 0x61 && buffer[5] == 0xFC) {
                int rssi = (int)(buffer[9]);
                if (rssi) {
                    rssi = 256 - rssi;
                    DBGPRINT(ERROR, "%sPacket header is RSSI%s, %shandle%s:0x%02X%02X, %sRSSI%s:-%d, read = %d, ",
                            LIGHT_CYAN, NONECOLOR,
                            LIGHT_CYAN, NONECOLOR, buffer[8], buffer[7],
                            LIGHT_CYAN, NONECOLOR, rssi, nRead);
                }
            } else if (buffer[4] == 0x11 && buffer[5] == 0xFD) {
                int link_number = (int)(buffer[15]);
                int i;

                DBGPRINT(SHOW, "%slink_number%s = %d", LIGHT_CYAN, NONECOLOR, link_number);
                DBGPRINT(SHOW, "%sBT Tx Count%s = %d and Rx Count = %d , LE Tx Count = %d and Rx Count = %d",
                        LIGHT_CYAN, NONECOLOR,
                        buffer[7] + (buffer[8] << 8), buffer[9] + (buffer[10] << 8), buffer[11] + (buffer[12] << 8), buffer[13] + (buffer[14] << 8));
                for ( i = 0; i < link_number; i++) {
                    int index = 16 + 26 * i;
                    uint32_t per_link_tx_count = 0;
                    uint32_t per_link_tx_total_count = 0;
                    uint32_t per_link_tx_error_count = 0;
                    uint32_t per_link_tx_per = 0;
                    uint32_t per_link_rx_count = 0;
                    uint32_t per_link_rx_total_count = 0;
                    uint32_t per_link_rx_error_count = 0;
                    uint32_t per_link_rx_per = 0;
                    double l2cap_avg = 0;
                    double l2cap_max = 0;
                    DBGPRINT(SHOW, "%sBD_ADDRESS%s = %02X:%02X:%02X:%02X:%02X:%02X",
                            LIGHT_CYAN, NONECOLOR,
                            buffer[index + 5], buffer[index + 4], buffer[index + 3],
                            buffer[index + 2], buffer[index + 1], buffer[index]);
                    DBGPRINT(SHOW, "%sType of Link%s = %s",
                            LIGHT_CYAN, NONECOLOR,
                            buffer[index + 6]==(uint8_t)0?"BT Master":
                            buffer[index + 6]==(uint8_t)1?"BT Slave":
                            buffer[index + 6]==(uint8_t)2?"BLE Master":
                            buffer[index + 6]==(uint8_t)3?"BLE SLave":"Unknown");

                    per_link_tx_count = buffer[index + 7] + (buffer[index + 8] << 8);
                    per_link_tx_total_count = buffer[index + 9] + (buffer[index + 10] << 8);
                    per_link_tx_error_count = buffer[index + 11] + (buffer[index + 12] << 8);
                    if (per_link_tx_total_count)
                        per_link_tx_per = ((per_link_tx_error_count*100) / per_link_tx_total_count);

                    DBGPRINT(SHOW, "%sPacket Tx Count of Link%s = %d", LIGHT_CYAN, NONECOLOR, per_link_tx_count);
                    DBGPRINT(SHOW, "%sTX Per%s = %d (%d/%d)", LIGHT_CYAN, NONECOLOR, per_link_tx_per, per_link_tx_error_count, per_link_tx_total_count);

                    per_link_rx_count = buffer[index + 13] + (buffer[index + 14] << 8);
                    per_link_rx_total_count = buffer[index + 15] + (buffer[index + 16] << 8);
                    per_link_rx_error_count = buffer[index + 17] + (buffer[index + 18] << 8);
                    if (per_link_rx_total_count)
                        per_link_rx_per = ((per_link_rx_error_count*100) / per_link_rx_total_count);

                    DBGPRINT(SHOW, "%sPacket Rx Count of Link%s = %d", LIGHT_CYAN, NONECOLOR, per_link_rx_count);
                    DBGPRINT(SHOW, "%sRX PER%s  = %d (%d/%d)", LIGHT_CYAN, NONECOLOR, per_link_rx_per, per_link_rx_error_count, per_link_rx_total_count);

                    DBGPRINT(SHOW, "%sTx Power Lower Bound Index%s = %d, Last Used Tx Power Index = %d",
                            LIGHT_CYAN, NONECOLOR,
                            buffer[index + 19], buffer[index + 20]);
                    DBGPRINT(SHOW, "%sLast Used Tx Power in dBm%s = %d dBm",
                            LIGHT_CYAN, NONECOLOR,
                            (int8_t)buffer[index + 21]);
                    l2cap_avg =  buffer[index + 22] + (buffer[index + 23] << 8);
                    DBGPRINT(SHOW, "%sAverage L2CAP Out latency%s = %.f, %.9f ms",
                            LIGHT_CYAN, NONECOLOR,
                            l2cap_avg, l2cap_avg * 0.3125);
                    l2cap_max =  buffer[index + 24] + (buffer[index + 25] << 8);
                    DBGPRINT(SHOW, "%sMaximum L2CAP Out latency%s = %.f, %.9f ms",
                            LIGHT_CYAN, NONECOLOR,
                            l2cap_max, l2cap_max * 0.3125);
                }
            } else {
                switch (buffer[0]) {
                    case DATA_TYPE_COMMAND:
                        /* it's for hci command */
                        bperf_notify_cmd(&buffer[1], nRead - 1);
                        DBGPRINT(TRACE, "read = %d, Packet header is cmd %02X %02X %02X %02X %02X %02X",
                                nRead, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
                        break;
                    case DATA_TYPE_ACL:
                        bperf_notify_acl(&buffer[1], nRead - 1);
                        DBGPRINT(TRACE, "read = %d, Packet header is acl %02X %02X %02X %02X %02X %02X",
                                nRead, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
                        break;
                    case DATA_TYPE_EVENT:
                        /* it's for hci event */
                        bperf_notify_event(&buffer[1], nRead - 1);
                        if (Dhci_event_number > 0) {
                            PICUS_RAW_INFO(buffer, nRead - 1, "Dhci_event");
                            Dhci_event_number--;
                        }
                        DBGPRINT(TRACE, "read = %d, Packet header is event %02X %02X %02X %02X %02X %02X",
                                nRead, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
                        if (buffer[1] == HCE_CONNECTION_COMPLETE) {
                            if (buffer[12] == 0x01) {
                                DBGPRINT(SHOW, "(%sConnection_Complete%s)(ConnHandle:0x%04X)(ACL)", YELLOW, NONECOLOR, (((buffer[5] << 8) & 0xff00) | buffer[4]));
                            } else if (buffer[12] == 0x00) {
                                DBGPRINT(SHOW, "(%sConnection_Complete%s)(ConnHandle:0x%04X)(SCO)", YELLOW, NONECOLOR, (((buffer[5] << 8) & 0xff00) | buffer[4]));
                            } else {
                                DBGPRINT(SHOW, "(%sConnection_Complete%s)(ConnHandle:0x%04X)", YELLOW, NONECOLOR, ((buffer[5] << 8 & 0xff00) | buffer[4]));
                            }
                        }
                        else if (buffer[1] == HCE_COMMAND_COMPLETE) {
                            if (buffer[4] == 0xFF) {
                                DBGPRINT(SHOW, "RSSI:%d Channel:%d", (int8_t)buffer[5], buffer[6]);
                            }
                            else if (buffer[4] == 0x06 &&  buffer[5] == 0x14) {
                                DBGPRINT(SHOW, "Connection_Handle:0x%02X%02X AFH_Mode:%d AFH:%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", buffer[8], buffer[7], buffer[9],
                                        buffer[10], buffer[11], buffer[12], buffer[13],buffer[14],
                                        buffer[15], buffer[16], buffer[17], buffer[18],buffer[19]);
                            }
                        }
                        break;
                    default:
                        DBGPRINT(ERROR, "read = %d, Packet header is not not fw log %02X %02X %02X %02X %02X %02X",
                                nRead, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
                        break;
                }
            }
            ret = 0;
        } else {
            ++ret;
        }
    } while (cont);

done:
    if (buf_size) {
        buf_size = 0;
        free(buf);
    }

    /* unlock the device node */
    unlock_device_node(fd, &fl, OSI_F_UNLCK, OSI_SEEK_SET);

    if (fd > 0) osi_close(fd);
    if (fscript) {
        DBGPRINT(SHOW, "release %s", dump_file_name);
        osi_fclose(fscript);
    }
    if (fw_dump_fscript) {
        DBGPRINT(SHOW, "release %s", fw_dump_file_name);
        osi_fclose(fw_dump_fscript);
        fw_dump_fscript = NULL;
        coredump_end = 0;
    }

    return 0;
}
//---------------------------------------------------------------------------
