/* Copyright Statement:
 *
 * This software/firmware and related documentation ("MediaTek Software") are
 * protected under relevant copyright laws. The information contained herein is
 * confidential and proprietary to MediaTek Inc. and/or its licensors. Without
 * the prior written permission of MediaTek inc. and/or its licensors, any
 * reproduction, modification, use or disclosure of MediaTek Software, and
 * information contained herein, in whole or in part, shall be strictly
 * prohibited.
 *
 * MediaTek Inc. (C) 2010. All rights reserved.
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

#ifndef __BT_BPERF_IF_H__
#define __BT_BPERF_IF_H__
#include "common.h"
#if defined(OS_FRTOS) || !defined(HELP_COLOR_SUPPORT)
#define NONECOLOR       ""
#define GRAY            ""
#define RED             ""
#define LIGHT_RED       ""
#define GREEN           ""
#define LIGHT_GREEN     ""
#define BROWN           ""
#define YELLOW          ""
#define BLUE            ""
#define LIGHT_BLUE      ""
#define PURPLE          ""
#define LIGHT_PURPLE    ""
#define CYAN            ""
#define LIGHT_CYAN      ""
#define LIGHT_WHITE     ""
#else
#define NONECOLOR       "\033[m"
#define GRAY            "\033[1;30m"
#define RED             "\033[0;31m"
#define LIGHT_RED       "\033[1;31m"
#define GREEN           "\033[0;32m"
#define LIGHT_GREEN     "\033[1;32m"
#define BROWN           "\033[0;33m"
#define YELLOW          "\033[1;33m"
#define BLUE            "\033[0;34m"
#define LIGHT_BLUE      "\033[1;34m"
#define PURPLE          "\033[0;35m"
#define LIGHT_PURPLE    "\033[1;35m"
#define CYAN            "\033[0;36m"
#define LIGHT_CYAN      "\033[1;36m"
#define LIGHT_WHITE     "\033[1;37m"
#endif

enum{
    BPERF_STATE_UNKNOWN,
    BPERF_STATE_THREAD_RUNNING,
    BPERF_STATE_THREAD_STOPPED
};

enum{
    BPERF_DATA_TYPE_HOGP,
    BPERF_DATA_TYPE_HID,
    BPERF_DATA_TYPE_A2DP,
    BPERF_DATA_TYPE_VOICE,
    BPERF_DATA_TYPE_UNKNOWN
};

enum{
    BPERF_BLE_ADV_TYPE_CONNECTABLE_UNDIRECTED = 0x00,
    BPERF_BLE_ADV_TYPE_CONNECTABLE_DIRECTED = 0x01,
    BPERF_BLE_ADV_TYPE_SCANNABLE_DIRECTED = 0x02,
    BPERF_BLE_ADV_TYPE_NON_CONNECTABLE_UNDIRECTED = 0x03,
    BPERF_BLE_ADV_TYPE_SCAN_RESPONSE = 0x04
};

struct bperf_event {
    unsigned short id;
    unsigned int time;
    unsigned int buf_len;
    unsigned int extra_info;
};

void bperf_notify_cmd(const uint8_t *buf, const unsigned int buf_len);
void bperf_notify_event(const uint8_t *buf, const unsigned int buf_len);
void bperf_notify_acl(const uint8_t *buf, const unsigned int buf_len);
void bperf_set_average_timer(const unsigned int average_timer);
void bperf_init();
void bperf_uninit();
void bperf_mem_init(int init_type);

#define BPERF_VOICE 0
#define BPERF_RC 1
#define BPERF_HID 2
#define BPERF_HOGP 3
#define BPERF_A2DP 4
#define BPERF_BLE_SCAN 5


#endif
