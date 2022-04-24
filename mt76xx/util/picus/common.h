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

#ifndef _COMMON_H_
#define _COMMON_H_

/* --------------------------------------------------------------------------- */
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>

/* --------------------------------------------------------------------------- */
#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#ifdef OS_FRTOS
#define FD_DRIVER_DBGNODE  0x01
#define FD_HCIFIFO  0x02
#define FD_PICUS_FILE   0x03
#define FD_FWDUMP_FILE   0x04
#endif
/* --------------------------------------------------------------------------- */
/* This device node only for read firmware log */
#define CUST_BT_FWLOG_PORT  "/dev/stpbtfwlog"
#define HCI_FIFO_PATH "/tmp/Dhci_myfifo"
/* Picus log default PATH is /data/misc/bluedroid/dump_0.picus */
/* FW dump default PATH is /data/misc/bluedroid/fw_dump.picus */
#define DEFAULT_PATH "/data/misc/bluedroid"
#define DUMP_PICUS_NAME_PREFIX "dump_"
#define DUMP_PICUS_NAME_EXT ".picus"
#define FW_DUMP_PICUS_NAME_PREFIX "fw_dump_"


#define RETRY_COUNT         20
#define FW_LOG_SWITCH_SIZE  20 * 1024 * 1024
#define MT_TIMEOUT_VALUE    1000
#define IOC_MAGIC           0xb0

#define HCI_COMMAND_TPYE_LENGTH 1
#define HCI_ACL_TPYE_LENGTH 2
/* add get chip id(ex:7668...) */
#define IOCTL_GET_CHIP_ID                           _IOWR('H', 1, int)
/* add for BT Tool, change ALTERNATE_SETTING for SCO */
#define IOCTL_CHANGE_ALTERNATE_SETTING_INTERFACE    _IOWR(IOC_MAGIC, 2, unsigned long)

/* HCI Event = 04(HCI Type : 1 byte) + Event Code(1 byte) + Patameter(MAX is 0xFF : 255 bytes) */
#define HCI_MAX_EVENT_SIZE              257
#define HCE_CONNECTION_COMPLETE         0x03
#define HCE_COMMAND_COMPLETE            0x0E

/** Debugging Feature : hci-base interaction mode */
#define D_FIFO_DATA "hci"

/* --------------------------------------------------------------------------- */
typedef enum _MT_DEBUG_LEVEL
{
    SHOW,       // debug off, priority highest
    ERROR,      // only show eror
    WARN,
    TRACE,
    DEEPTRACE,
    HCITRACE,
} MT_DEBUG_LEVEL;

typedef enum _MT_API_RESULT
{
    MT_RESULT_FAIL = -1,
    MT_RESULT_SUCCESS,
} MMT_API_RESULT;

typedef enum {
    DATA_TYPE_COMMAND = 1,
    DATA_TYPE_ACL     = 2,
    DATA_TYPE_SCO     = 3,
    DATA_TYPE_EVENT   = 4
} serial_data_type_t;

/* --------------------------------------------------------------------------- */
void DBGPRINT(int level, const char *format, ...);

#define PICUS_RAW_INFO(p, l, fmt, ...)                  \
    do {                                                \
        int raw_count = 0;                              \
        const unsigned char *ptr = p;                   \
        printf("[picus] "fmt, ##__VA_ARGS__);           \
        for (raw_count = 0; raw_count < l; ++raw_count) \
            printf(" %02X", ptr[raw_count]);            \
        printf("\n");                                   \
    } while (0)

#endif /* _COMMON_H_ */
