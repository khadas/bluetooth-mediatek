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

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include "bperf_util.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#include "common.h"
#ifdef OS_FRTOS
#include "osi_frtos.h"
#else
#include "osi_linux.h"
#endif

#define BPERF_LIBRARY_VERSION "700.0.19011501"
#define LOG_TAG "bperf"
#define MAX_BPERF_EVENTS_IN_A_SECOND 500
#define MAX_BPERF_LE_SCAN_ENTRY 64
#define MAX_BPERF_BT_SCAN_ENTRY 64

#ifdef OS_FRTOS
static SemaphoreHandle_t  event_data_lock;
#else
static PTHREAD_MUTEX_T event_data_lock;
#endif
static PTHREAD_T bperf_thread_main;
static unsigned int bperf_main_thread_status;
static unsigned int bperf_main_thread_should_stop;
static unsigned int bperf_global_counter;
static uint8_t bperf_global_bitpool;
static uint8_t bperf_global_voble_codec; /* 0: ADPCM, 1:OPUS */
static unsigned char bperf_a2dp_string_interval[64];
static unsigned char bperf_a2dp_string_throughput[64];
static unsigned char bperf_a2dp_string_bitpool[64];

static unsigned int bperf_average_accumulate;
static unsigned int bperf_average_total_time;
static unsigned int bperf_average_total_time_index;

static int event_len_summary_rc_fw_upgrade = 0;
static int event_len_summary_voice = 0;
static int event_len_summary_voice_drop = 0;
static int event_len_summary_a2dp = 0;
static int event_len_summary_a2dp_glitch_warning = 0;
static int event_counter_summary_hid = 0;
static int event_counter_summary_hid_cursor = 0;
static int event_counter_summary_hogp = 0;
static int event_counter_summary_hogp_cursor = 0;
static int event_counter_summary_hid_delta_time_max = 0;
static int event_counter_summary_hid_cursor_delta_time_max = 0;
static int event_counter_summary_hogp_delta_time_max = 0;
static int event_counter_summary_hogp_cursor_delta_time_max = 0;
static int event_counter_summary_ble_adv = 0;

static struct bperf_event *bperf_event_voice, *bperf_event_voice_analysis;
static struct bperf_event *bperf_event_rc_fw_upgrade, *bperf_event_rc_fw_upgrade_analysis;
static struct bperf_event *bperf_event_hid, *bperf_event_hid_analysis;
static struct bperf_event *bperf_event_hid_cursor, *bperf_event_hid_cursor_analysis;
static struct bperf_event *bperf_event_hogp, *bperf_event_hogp_analysis;
static struct bperf_event *bperf_event_hogp_cursor, *bperf_event_hogp_cursor_analysis;
static struct bperf_event *bperf_event_a2dp, *bperf_event_a2dp_analysis;
static struct bperf_event *bperf_event_ble_scan, *bperf_event_ble_scan_analysis;

static unsigned int _bperf_get_microseconds(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec * 1000000 + now.tv_usec);
}

static void _bperf_mem_record_event(struct bperf_event* event, const uint8_t *buf, const unsigned int buf_len)
{
    int i;
    (void)buf;

    for ( i = 0 ; i < MAX_BPERF_EVENTS_IN_A_SECOND ; i++ )
    {
        if ( event[i].id == 0 && event[i].time == 0 )
        {
            osi_pthread_mutex_lock(&event_data_lock);

            event[i].id = 1+i;
            event[i].time = _bperf_get_microseconds();
            event[i].buf_len = buf_len;

            /* BLE ADV Report, save event type */
            if ( buf[0] == 0x3e && buf[2] == 0x02 )
            {
                event[i].extra_info = buf[4];
            }
            /* HT RC Voice Search (2640)(BLE Data Length Extension) */
            else if ( buf_len == 111 && buf[2] == 0x6b && buf[3] == 0x00 && buf[8] == 0x1b && buf[9] == 0x3f && buf[10] == 0x00 )
            {
                event[i].extra_info = ((buf[11] >>3 )& 0x1F);
            }
            osi_pthread_mutex_unlock(&event_data_lock);
            break;
        }
    }
}

static void _bperf_mem_reset()
{
    if ( bperf_event_voice )
        memset(bperf_event_voice, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_rc_fw_upgrade )
        memset(bperf_event_rc_fw_upgrade, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_hid )
        memset(bperf_event_hid, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_hid_cursor )
        memset(bperf_event_hid_cursor, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_hogp )
        memset(bperf_event_hogp, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_hogp_cursor )
        memset(bperf_event_hogp_cursor, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_a2dp )
        memset(bperf_event_a2dp, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_ble_scan )
        memset(bperf_event_ble_scan, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
}

static void _bperf_mem_reset_analysis()
{
    if ( bperf_event_voice_analysis )
        memset(bperf_event_voice_analysis, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_rc_fw_upgrade_analysis )
        memset(bperf_event_rc_fw_upgrade_analysis, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_hid_analysis )
        memset(bperf_event_hid_analysis, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_hid_cursor_analysis )
        memset(bperf_event_hid_cursor_analysis, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_hogp_analysis )
        memset(bperf_event_hogp_analysis, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_hogp_cursor_analysis )
        memset(bperf_event_hogp_cursor_analysis, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_a2dp_analysis )
        memset(bperf_event_a2dp_analysis, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
    if ( bperf_event_ble_scan_analysis )
        memset(bperf_event_ble_scan_analysis, 0, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
}

void bperf_mem_init(int init_type)
{
    printf("%s init_type (%d)\n", __func__, init_type);
    switch (init_type) {
    case BPERF_VOICE:
        if ( bperf_event_voice == NULL )
            bperf_event_voice = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

        if ( bperf_event_voice_analysis == NULL )
            bperf_event_voice_analysis = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        break;

    case BPERF_RC:
        if ( bperf_event_rc_fw_upgrade == NULL )
            bperf_event_rc_fw_upgrade = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

        if ( bperf_event_rc_fw_upgrade_analysis == NULL )
            bperf_event_rc_fw_upgrade_analysis = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        break;

    case BPERF_HID:
        if ( bperf_event_hid == NULL )
            bperf_event_hid = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        if ( bperf_event_hid_cursor == NULL )
            bperf_event_hid_cursor = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

        if ( bperf_event_hid_analysis == NULL )
            bperf_event_hid_analysis = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        if ( bperf_event_hid_cursor_analysis == NULL )
            bperf_event_hid_cursor_analysis = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        break;

    case BPERF_HOGP:
        if ( bperf_event_hogp == NULL )
            bperf_event_hogp = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        if ( bperf_event_hogp_cursor == NULL )
            bperf_event_hogp_cursor= malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

        if ( bperf_event_hogp_analysis == NULL )
            bperf_event_hogp_analysis = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        if ( bperf_event_hogp_cursor_analysis == NULL )
            bperf_event_hogp_cursor_analysis = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        break;

    case BPERF_A2DP:
        if ( bperf_event_a2dp == NULL )
            bperf_event_a2dp = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

        if ( bperf_event_a2dp_analysis == NULL )
            bperf_event_a2dp_analysis = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        break;

    case BPERF_BLE_SCAN:
        if ( bperf_event_ble_scan == NULL )
            bperf_event_ble_scan = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

        if ( bperf_event_ble_scan_analysis == NULL )
            bperf_event_ble_scan_analysis = malloc(sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
        break;

    default:
        printf("%s init_type error (%d)", __func__, init_type);
    }


    _bperf_mem_reset();
    _bperf_mem_reset_analysis();
}

static void _bperf_mem_free()
{
    if ( bperf_event_voice )
        free(bperf_event_voice);
    if ( bperf_event_rc_fw_upgrade )
        free(bperf_event_rc_fw_upgrade);
    if ( bperf_event_hid )
        free(bperf_event_hid);
    if ( bperf_event_hid_cursor )
        free(bperf_event_hid_cursor);
    if ( bperf_event_hogp )
        free(bperf_event_hogp);
    if ( bperf_event_hogp_cursor )
        free(bperf_event_hogp_cursor);
    if ( bperf_event_a2dp )
        free(bperf_event_a2dp);
    if ( bperf_event_ble_scan )
        free(bperf_event_ble_scan);

    if ( bperf_event_voice_analysis )
        free(bperf_event_voice_analysis);
    if ( bperf_event_rc_fw_upgrade_analysis )
        free(bperf_event_rc_fw_upgrade_analysis);
    if ( bperf_event_hid_analysis )
        free(bperf_event_hid_analysis);
    if ( bperf_event_hid_cursor_analysis )
        free(bperf_event_hid_cursor_analysis);
    if ( bperf_event_hogp_analysis )
        free(bperf_event_hogp_analysis);
    if ( bperf_event_hogp_cursor_analysis )
        free(bperf_event_hogp_cursor_analysis);
    if ( bperf_event_a2dp_analysis )
        free(bperf_event_a2dp_analysis);
    if ( bperf_event_ble_scan_analysis )
        free(bperf_event_ble_scan_analysis);
}

static void _bperf_mem_copy()
{
    if (bperf_event_voice_analysis && bperf_event_voice)
        memcpy(bperf_event_voice_analysis, bperf_event_voice, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

    if (bperf_event_rc_fw_upgrade_analysis && bperf_event_rc_fw_upgrade)
        memcpy(bperf_event_rc_fw_upgrade_analysis, bperf_event_rc_fw_upgrade, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

    if (bperf_event_hid_analysis && bperf_event_hid)
        memcpy(bperf_event_hid_analysis, bperf_event_hid, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

    if (bperf_event_hid_cursor_analysis && bperf_event_hid_cursor)
        memcpy(bperf_event_hid_cursor_analysis, bperf_event_hid_cursor, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

    if (bperf_event_hogp_analysis && bperf_event_hogp)
        memcpy(bperf_event_hogp_analysis, bperf_event_hogp, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

    if (bperf_event_hogp_cursor_analysis && bperf_event_hogp_cursor)
        memcpy(bperf_event_hogp_cursor_analysis, bperf_event_hogp_cursor, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

    if (bperf_event_a2dp_analysis && bperf_event_a2dp)
        memcpy(bperf_event_a2dp_analysis, bperf_event_a2dp, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);

    if (bperf_event_ble_scan_analysis && bperf_event_ble_scan)
        memcpy(bperf_event_ble_scan_analysis, bperf_event_ble_scan, sizeof(struct bperf_event) * MAX_BPERF_EVENTS_IN_A_SECOND);
}

static void _bperf_analysis_rc_fw_upgrade(struct bperf_event *bperf_event)
{
    if ( bperf_event )
    {
        int i;
        int event_counter=0;
        int event_len_total=0;

        for ( i = 0 ; i < MAX_BPERF_EVENTS_IN_A_SECOND ; i++ )
        {
            if ( bperf_event[i].id )
            {
                event_counter++;
                event_len_total += (bperf_event[i].buf_len - 4); /* 4 byte hci header should be removed */
            }
            else
            {
                break;
            }
        }

        if ( i > 0 )
        {
            if ( bperf_average_accumulate == 1 )
            {
                event_len_summary_rc_fw_upgrade += event_len_total;
            }

            printf("[bperf](%d) RC FW Upgrade Num(%d), Throughput (%d bps)\n", bperf_global_counter, event_counter, (event_len_total<<3));
        }
    }
}

static void _bperf_analysis_voice(struct bperf_event *bperf_event)
{
    if ( bperf_event )
    {
        int i;
        int event_counter = 0;
        int event_len_total = 0;
        int event_len_voice = 0;
        int event_counter_packet_drop = 0;
        int event_counter_packet_not_in_time = 0;
        int event_delta_time = 0;
        int event_max_delta_time = 0;
        static int latest_voice_data_seq = 0;
        static int latest_voice_data_timestamp = 0;

        for ( i = 0 ; i < MAX_BPERF_EVENTS_IN_A_SECOND ; i++ )
        {
            if ( bperf_event[i].id )
            {
                event_counter++;

                /* Voice data packet contains 4 bytes hci header, 4 bytes l2cap header, 3 bytes ATT header, 1 bytes rc header, 19 bytes audio data */
                event_len_total += (bperf_event[i].buf_len - 4);
                event_len_voice += (bperf_event[i].buf_len - 11);

                if ( i > 0 )
                {
                    /* check sequence num */
                    if ( bperf_event[i].extra_info != 0 && bperf_event[i].extra_info - bperf_event[i-1].extra_info != 1 )
                    {
                        event_counter_packet_drop++;
                    }
                    else if ( bperf_event[i].extra_info == 0 && bperf_event[i-1].extra_info != 0 && bperf_event[i-1].extra_info != 31 )
                    {
                        event_counter_packet_drop++;
                    }

                    /* check delta time */
                    event_delta_time = bperf_event[i].time - bperf_event[i-1].time;
                    if ( event_delta_time > 30000 )
                    {
                        event_counter_packet_not_in_time++;
                    }

                    latest_voice_data_seq = bperf_event[i].extra_info;
                    latest_voice_data_timestamp = bperf_event[i].time;
                }
                else if ( i == 0 )
                {
                    /* check sequence num */
                    if ( bperf_event[i].extra_info != 0 && bperf_event[i].extra_info - latest_voice_data_seq != 1 )
                    {
                        event_counter_packet_drop++;
                    }
                    else if ( bperf_event[i].extra_info == 0 && latest_voice_data_seq != 0 && latest_voice_data_seq != 31 )
                    {
                        event_counter_packet_drop++;
                    }

                    /* check delta time */
                    event_delta_time = bperf_event[i].time - latest_voice_data_timestamp;
                    if ( bperf_event[i].time - latest_voice_data_timestamp > 30000 )
                    {
                        event_counter_packet_not_in_time++;
                    }
                    event_max_delta_time = event_delta_time;
                }

                /* check max delta time */
                if ( event_delta_time > event_max_delta_time )
                {
                    event_max_delta_time = event_delta_time;
                }
            }
            else
            {
                break;
            }
        }

        if ( i > 0 )
        {
            if ( bperf_average_accumulate == 1 )
            {
                event_len_summary_voice += event_len_voice;
                event_len_summary_voice_drop += event_counter_packet_drop;
            }

            if (bperf_global_voble_codec == 0)  /* codec : ADPCM */
            {
                /* Normal ADPCM voice data rate is abount 66,400 bps. */
                printf("[bperf](%d) VOICE Num(%d), " LIGHT_BLUE ", Voice Data Rate%s(%d bps), Packet Drop%s(%d), Not in time%s(%d), Max Latency%s(%dms)\n",
                                bperf_global_counter,
                                event_counter,
                                (event_len_voice<<3)<60000?LIGHT_RED:GREEN,
                                (event_len_voice<<3),
                                event_counter_packet_drop>0?LIGHT_RED:GREEN,
                                event_counter_packet_drop,
                                event_counter_packet_not_in_time>0?YELLOW:GREEN,
                                event_counter_packet_not_in_time,
                                event_max_delta_time>30000?YELLOW:GREEN,
                                event_max_delta_time/1000);
            }
            else    /* codec : OPUS */
            {
                /* Normal ADPCM voice data rate is abount 16,800 bps. */
                printf("[bperf](%d) VOICE Num(%d), Voice Data Rate %s(%d bps)\n",
                                bperf_global_counter,
                                event_counter,
                                (event_len_voice<<3)<1500?LIGHT_RED:GREEN,
                                (event_len_voice<<3));
            }
        }
    }
}

static void _bperf_analysis_hid_hogp(struct bperf_event *bperf_event)
{
    if ( bperf_event )
    {
        int i;
        int event_counter=0;
        int delta_time=0;
        int delta_time_max=0;

        for ( i = 0 ; i < MAX_BPERF_EVENTS_IN_A_SECOND ; i++ )
        {
            if ( bperf_event[i].id )
            {
                event_counter++;
                if ( i == 0 )
                {
                    delta_time = 0;
                    delta_time_max = 0;
                }
                else
                {
                    delta_time = bperf_event[i].time - bperf_event[i-1].time;
                    if ( delta_time > delta_time_max )
                        delta_time_max = delta_time;
                }
            }
            else
            {
                break;
            }
        }

        if ( i > 0 )
        {
            if ( bperf_event == bperf_event_hid_analysis )
            {
                if ( bperf_average_accumulate == 1 )
                {
                    event_counter_summary_hid += event_counter;
                    if ( delta_time_max > event_counter_summary_hid_delta_time_max )
                        event_counter_summary_hid_delta_time_max = delta_time_max;
                }

                printf("[bperf](%d) %sHID Input Report Num%s(%d) %sMax_Delta_Time%s(%dms)\n",
                        bperf_global_counter,
                        CYAN, NONECOLOR, event_counter,
                        CYAN, NONECOLOR, delta_time_max/1000);
            }
            else if ( bperf_event == bperf_event_hid_cursor_analysis )
            {
                if ( bperf_average_accumulate == 1 )
                {
                    event_counter_summary_hid_cursor += event_counter;
                    if ( delta_time_max > event_counter_summary_hid_cursor_delta_time_max )
                        event_counter_summary_hid_cursor_delta_time_max = delta_time_max;
                }

                printf("[bperf](%d) %sHID_Mouse Input Report Num%s(%d) %sMax_Delta_Time%s(%dms)\n",
                        bperf_global_counter,
                        CYAN, NONECOLOR, event_counter,
                        CYAN, NONECOLOR, delta_time_max/1000);
            }
            else if ( bperf_event == bperf_event_hogp_analysis )
            {
                if ( bperf_average_accumulate == 1 )
                {
                    event_counter_summary_hogp += event_counter;
                    if ( delta_time_max > event_counter_summary_hogp_delta_time_max )
                        event_counter_summary_hogp_delta_time_max = delta_time_max;
                }

                printf("[bperf](%d) %sHOGP Input Report Num%s(%d) %sMax_Delta_Time%s(%dms)\n",
                        bperf_global_counter,
                        CYAN, NONECOLOR, event_counter,
                        CYAN, NONECOLOR, delta_time_max/1000);
            }
            else if ( bperf_event == bperf_event_hogp_cursor_analysis )
            {
                if ( bperf_average_accumulate == 1 )
                {
                    event_counter_summary_hogp_cursor += event_counter;
                    if ( delta_time_max > event_counter_summary_hogp_cursor_delta_time_max )
                        event_counter_summary_hogp_cursor_delta_time_max = delta_time_max;
                }

                printf("[bperf](%d) %sHOGP_Mouse Input Report Num%s(%d) %sMax_Delta_Time%s(%dms)\n",
                        bperf_global_counter,
                        CYAN, NONECOLOR, event_counter,
                        CYAN, NONECOLOR, delta_time_max/1000);
            }
        }
    }
}

static void _bperf_analysis_a2dp(struct bperf_event *bperf_event)
{
    if ( bperf_event )
    {
        int i;
        int event_counter=0;
        int delta_time_max=0;
        int delta_time_min=0;
        int delta_time_average=0;
        int delta_time=0;
        int event_len_total=0;

        for ( i = 0 ; i < MAX_BPERF_EVENTS_IN_A_SECOND ; i++ )
        {
            if ( bperf_event[i].id )
            {
                event_counter++;
                /* A2DP data packet contains 4byte HCI header, 4 byte L2CAP header, 12 byte AVDTP header*/
                event_len_total += (bperf_event[i].buf_len - 20);
                if ( i == 0 )
                {
                    delta_time_max = delta_time_average = 0;
                    delta_time_min = 999999999;
                }
                else
                {
                    if ( bperf_event[i].time > bperf_event[i-1].time )
                        delta_time = bperf_event[i].time - bperf_event[i-1].time;
                    else
                        delta_time = 0;

                    if ( delta_time > delta_time_max )
                        delta_time_max = delta_time;
                    if ( delta_time < delta_time_min )
                        delta_time_min = delta_time;
                    delta_time_average += delta_time;
                }
            }
            else
            {
                break;
            }
        }

        if ( i > 0 )
        {
            if ( bperf_average_accumulate == 1 )
            {
                event_len_summary_a2dp += event_len_total;
            }

            delta_time_average = delta_time_average/i;
            memset(bperf_a2dp_string_interval, 0, sizeof(bperf_a2dp_string_interval));
            memset(bperf_a2dp_string_throughput, 0, sizeof(bperf_a2dp_string_throughput));
            memset(bperf_a2dp_string_bitpool, 0, sizeof(bperf_a2dp_string_bitpool));

            /* bitpool */
            if ( bperf_global_bitpool != 51 && bperf_global_bitpool != 53 )
                snprintf((char*)bperf_a2dp_string_bitpool, sizeof(bperf_a2dp_string_bitpool), "%sBitpool%s(%d)%s", LIGHT_PURPLE, YELLOW, bperf_global_bitpool, NONECOLOR);
            else
                snprintf((char*)bperf_a2dp_string_bitpool, sizeof(bperf_a2dp_string_bitpool), "%sBitpool%s(%d)%s", LIGHT_PURPLE, NONECOLOR, bperf_global_bitpool, NONECOLOR);

            /* delta time */
            if (delta_time_max > 150000)
            {
                snprintf((char*)bperf_a2dp_string_interval, sizeof(bperf_a2dp_string_interval), "%sMaxInterval%s(%dms)%s", LIGHT_PURPLE, LIGHT_RED, delta_time_max/1000, NONECOLOR);
                event_len_summary_a2dp_glitch_warning++;
            }
            else if (delta_time_max <= 150000 && delta_time_max > 100000)
                snprintf((char*)bperf_a2dp_string_interval, sizeof(bperf_a2dp_string_interval), "%sMaxInterval%s(%dms)%s", LIGHT_PURPLE, YELLOW, delta_time_max/1000, NONECOLOR);
            else
                snprintf((char*)bperf_a2dp_string_interval, sizeof(bperf_a2dp_string_interval), "%sMaxInterval%s(%dms)%s", LIGHT_PURPLE, NONECOLOR, delta_time_max/1000, NONECOLOR);

            /* data rate */
            /* 90% : 328*1024*0.9  = 302285 */
            /* 85% : 328*1024*0.85 = 285491 */
            if ((event_len_total<<3) < 285491)
            {
                event_len_summary_a2dp_glitch_warning++;
                snprintf((char*)bperf_a2dp_string_throughput, sizeof(bperf_a2dp_string_throughput), "%sThroughput%s(%d kbps)%s", LIGHT_PURPLE, LIGHT_RED, (event_len_total>>7), NONECOLOR);
            }
            else if ((event_len_total<<3) >= 285491 && (event_len_total<<3) < 302285)
                snprintf((char*)bperf_a2dp_string_throughput, sizeof(bperf_a2dp_string_throughput), "%sThroughput%s(%d kbps)%s", LIGHT_PURPLE, YELLOW, (event_len_total>>7), NONECOLOR);
            else
                snprintf((char*)bperf_a2dp_string_throughput, sizeof(bperf_a2dp_string_throughput), "%sThroughput%s(%d kbps)%s", LIGHT_PURPLE, NONECOLOR, (event_len_total>>7), NONECOLOR);

            printf("[bperf](%d) %sA2DP Num%s(%d), %s, %s, %s\n",
                  bperf_global_counter, LIGHT_PURPLE, NONECOLOR, event_counter, bperf_a2dp_string_bitpool, bperf_a2dp_string_interval, bperf_a2dp_string_throughput);

        }
    }
}

static void _bperf_analysis_ble_scan(struct bperf_event *bperf_event)
{
    if ( bperf_event )
    {
        int i;
        int event_counter = 0;
        int event_counter_connectable_undirected = 0;
        int event_counter_connectable_directed = 0;
        int event_counter_scannable_directed = 0;
        int event_counter_non_connectable_undirected = 0;
        int event_counter_scan_response = 0;

        for ( i = 0 ; i < MAX_BPERF_EVENTS_IN_A_SECOND ; i++ )
        {
            if ( bperf_event[i].id )
            {
                event_counter++;
                if ( bperf_event[i].extra_info == BPERF_BLE_ADV_TYPE_CONNECTABLE_UNDIRECTED )
                    event_counter_connectable_undirected++;
                else if ( bperf_event[i].extra_info == BPERF_BLE_ADV_TYPE_CONNECTABLE_DIRECTED )
                    event_counter_connectable_directed++;
                else if ( bperf_event[i].extra_info == BPERF_BLE_ADV_TYPE_SCANNABLE_DIRECTED )
                    event_counter_scannable_directed++;
                else if ( bperf_event[i].extra_info == BPERF_BLE_ADV_TYPE_NON_CONNECTABLE_UNDIRECTED )
                    event_counter_non_connectable_undirected++;
                else if ( bperf_event[i].extra_info == BPERF_BLE_ADV_TYPE_SCAN_RESPONSE )
                    event_counter_scan_response++;
            }
            else
            {
                break;
            }
        }

        if ( i > 0 )
        {
            if ( bperf_average_accumulate == 1 )
            {
                event_counter_summary_ble_adv += event_counter;
            }

            printf("[bperf](%d) %sBLE ADV Num%s(%d) (%sconn_undir%s:%d)(%sconn_dir%s:%d)(%ssca_dir%s:%d)(%snon-conn_undir%s:%d)(%sscan_resp%s:%d)\n",
                    bperf_global_counter,
                    LIGHT_GREEN, NONECOLOR,
                    event_counter,
                    LIGHT_GREEN, NONECOLOR,
                    event_counter_connectable_undirected,
                    NONECOLOR, NONECOLOR,
                    event_counter_connectable_directed,
                    NONECOLOR, NONECOLOR,
                    event_counter_scannable_directed,
                    NONECOLOR, NONECOLOR,
                    event_counter_non_connectable_undirected,
                    LIGHT_GREEN, NONECOLOR,
                    event_counter_scan_response);
        }
    }
}

static void _bperf_analysis_inquiry(const uint8_t *buf, const unsigned int buf_len)
{
    int i;
    int entry_found = MAX_BPERF_BT_SCAN_ENTRY;
    int entry_empty = MAX_BPERF_BT_SCAN_ENTRY;
    int entry_used = MAX_BPERF_BT_SCAN_ENTRY;
    int save_entry = 0;
    static unsigned int bt_scan_start_time;
    static unsigned int bt_scan_result_time[MAX_BPERF_BT_SCAN_ENTRY][3];
    static uint8_t bt_scan_result_address[MAX_BPERF_BT_SCAN_ENTRY][6];

    /* HCI_INQUIRY */
    if ( buf_len == 8 && buf[0] == 0x01 && buf[1] == 0x04 && buf[2] == 0x05 )
    {
        printf("[bperf] %sHCI_INQUIRY%s Started (Inquiry_Length:%.2fs)(0ms)\n",
                BLUE, NONECOLOR, (buf[6]*1.28));
        bt_scan_start_time = _bperf_get_microseconds();
        for ( i = 0 ; i < MAX_BPERF_LE_SCAN_ENTRY ; i++ )
        {
            bt_scan_result_time[i][0] = 0;
            bt_scan_result_time[i][1] = 0;
            bt_scan_result_time[i][2] = 0;
            bt_scan_result_address[i][0] = 0;
            bt_scan_result_address[i][1] = 0;
            bt_scan_result_address[i][2] = 0;
            bt_scan_result_address[i][3] = 0;
            bt_scan_result_address[i][4] = 0;
            bt_scan_result_address[i][5] = 0;
        }
    }
    /* HCI_EXTEND_INQUIRY_RESULT || HCI_REMOTE_NAME_REQUEST ||HCI_REMOTE_NAME_REQUEST_COMPLETE*/
    else if ( (buf[0] == 0x2f && buf[1] == 0xff && buf[2] == 0x01) ||
              (buf_len == 13 && buf[0] == 0x19 && buf[1] == 0x04 && buf[2] == 0x0a) ||
              (buf[0] == 0x07 && buf[1] == 0xff && buf[2] == 0x00) )
    {
        for ( i = 0 ; i < MAX_BPERF_BT_SCAN_ENTRY ; i++ )
        {
            if ( bt_scan_result_address[i][0] == 0 && bt_scan_result_address[i][1] == 0 && bt_scan_result_address[i][2] == 0 &&
                 bt_scan_result_address[i][3] == 0 && bt_scan_result_address[i][4] == 0 && bt_scan_result_address[i][5] == 0 )
            {
                entry_empty = i;
                break;
            }
        }

        for ( i = 0 ; i < MAX_BPERF_BT_SCAN_ENTRY ; i++ )
        {
            if ( strncmp((char*)(&bt_scan_result_address[i][0]), (char*)(&buf[3]), 6) == 0 )
            {
                entry_found = i;
                break;
            }
        }

        /* Entry found */
        if ( entry_found != MAX_BPERF_BT_SCAN_ENTRY )
        {
            save_entry = 1;
            entry_used = entry_found;
        }
        /* Entry not found, use empty entry */
        else if ( entry_found == MAX_BPERF_BT_SCAN_ENTRY && entry_empty != MAX_BPERF_BT_SCAN_ENTRY )
        {
            save_entry = 1;
            entry_used = entry_empty;
        }
        /* Entry full */
        else
        {
            save_entry = 0;
            printf("[bperf] HCI_EXTEND_INQUIRY_RESULT Entry FULL!! (%d)\n", MAX_BPERF_BT_SCAN_ENTRY);
        }

        if ( save_entry )
        {
            /* HCI_EXTEND_INQUIRY_RESULT */
            if ( buf[0] == 0x2f && buf[1] == 0xff && buf[2] == 0x01 )
            {
                strncpy((char*)(&bt_scan_result_address[entry_used][0]), (char*)(&buf[3]), 6);
                bt_scan_result_time[entry_used][0] = _bperf_get_microseconds();
                printf("[bperf] %sHCI_EXTEND_INQUIRY_RESULT%s (%d)(%02x:%02x:%02x:%02x:%02x:%02x)(%dms)\n",
                            LIGHT_BLUE, NONECOLOR,
                            entry_used, buf[8], buf[7], buf[6], buf[5], buf[4], buf[3],
                            (int)((bt_scan_result_time[entry_used][0]-bt_scan_start_time)/1000));
            }
            /* HCI_REMOTE_NAME_REQUEST */
            else if ( buf_len == 13 && buf[0] == 0x19 && buf[1] == 0x04 && buf[2] == 0x0a )
            {
                bt_scan_result_time[entry_used][1] = _bperf_get_microseconds();
                printf("[bperf] %sHCI_REMOTE_NAME_REQUEST%s (%d)(%02x:%02x:%02x:%02x:%02x:%02x)(%dms)\n",
                            LIGHT_BLUE, NONECOLOR,
                            entry_used, buf[8], buf[7], buf[6], buf[5], buf[4], buf[3],
                            (int)((bt_scan_result_time[entry_used][1]-bt_scan_start_time)/1000));
            }
            /* HCI_REMOTE_NAME_REQUEST_COMPLETE */
            else if ( buf[0] == 0x07 && buf[1] == 0xff && buf[2] == 0x00 )
            {
                bt_scan_result_time[entry_used][2] = _bperf_get_microseconds();
                printf("[bperf] %sHCI_REMOTE_NAME_REQUEST_COMPLETE%s (%d)(%02x:%02x:%02x:%02x:%02x:%02x)(%dms)(%s)\n",
                            LIGHT_BLUE, NONECOLOR,
                            entry_used, buf[8], buf[7], buf[6], buf[5], buf[4], buf[3],
                            (int)((bt_scan_result_time[entry_used][2]-bt_scan_start_time)/1000),
                            (char*)(&buf[9]));
            }
        }
        /* Duplicate, skip it */
        else
        {}
    }
    /* HCI_INQUIRY_COMPLETE */
    else if ( buf_len == 3 && buf[0] == 0x01 && buf[1] == 0x01 && buf[2] == 0x00 )
    {
        printf("[bperf] %sHCI_INQUIRY_COMPLETE%s (%dms)\n",
                BLUE, NONECOLOR, ((_bperf_get_microseconds()-bt_scan_start_time)/1000));
    }
}

static void _bperf_analysis()
{
    if ( bperf_event_ble_scan_analysis )
    {
        _bperf_analysis_ble_scan(bperf_event_ble_scan_analysis);
    }

    if ( bperf_event_a2dp_analysis )
    {
        _bperf_analysis_a2dp(bperf_event_a2dp_analysis);
    }

    if ( bperf_event_voice_analysis )
    {
        _bperf_analysis_voice(bperf_event_voice_analysis);
    }

    if ( bperf_event_rc_fw_upgrade_analysis )
    {
        _bperf_analysis_rc_fw_upgrade(bperf_event_rc_fw_upgrade_analysis);
    }

    if ( bperf_event_hid_analysis )
    {
        _bperf_analysis_hid_hogp(bperf_event_hid_analysis);
    }

    if ( bperf_event_hid_cursor_analysis )
    {
        _bperf_analysis_hid_hogp(bperf_event_hid_cursor_analysis);
    }

    if ( bperf_event_hogp_analysis )
    {
        _bperf_analysis_hid_hogp(bperf_event_hogp_analysis);
    }

    if ( bperf_event_hogp_cursor_analysis )
    {
        _bperf_analysis_hid_hogp(bperf_event_hogp_cursor_analysis);
    }

    if ( bperf_average_accumulate == 1 && bperf_average_total_time > 0 )
    {
        if ( bperf_average_total_time_index == 0 )
        {
            if ( bperf_average_total_time )
            {
                if ( event_counter_summary_ble_adv )
                {
                    printf("[bperf] %sBLE ADV Num(average)%s(%ds) (%d)\n",
                            YELLOW, NONECOLOR,
                            bperf_average_total_time, (event_counter_summary_ble_adv/bperf_average_total_time));
                    event_counter_summary_ble_adv = 0;
                }
                if ( event_len_summary_a2dp )
                {
                    printf("[bperf] %sA2DP(average)%s(%ds) Throughput (%d kbps) Audio Glitch Warning%s(%d)%s\n",
                            YELLOW, NONECOLOR,
                            bperf_average_total_time, (event_len_summary_a2dp<<3)/bperf_average_total_time/1000,
                            event_len_summary_a2dp_glitch_warning==0?NONECOLOR:LIGHT_RED,
                            event_len_summary_a2dp_glitch_warning,
                            NONECOLOR);
                    event_len_summary_a2dp = 0;
                    event_len_summary_a2dp_glitch_warning = 0;
                }
                if ( event_counter_summary_hid )
                {
                    printf("[bperf] %sHID(average)%s(%ds) Input Report Num (%d)  Max_Delta_Time(%dms)\n",
                            YELLOW, NONECOLOR,
                            bperf_average_total_time,
                            event_counter_summary_hid/bperf_average_total_time,
                            event_counter_summary_hid_delta_time_max/1000);
                    event_counter_summary_hid = 0;
                    event_counter_summary_hid_delta_time_max = 0;
                }
                if ( event_counter_summary_hid_cursor )
                {
                    printf("[bperf] %sHID_Mouse(average)%s(%ds) Input Report Num (%d)  Max_Delta_Time(%dms)\n",
                            YELLOW, NONECOLOR,
                            bperf_average_total_time,
                            event_counter_summary_hid_cursor/bperf_average_total_time,
                            event_counter_summary_hid_cursor_delta_time_max/1000);
                    event_counter_summary_hid_cursor = 0;
                    event_counter_summary_hid_cursor_delta_time_max = 0;
                }
                if ( event_counter_summary_hogp )
                {
                    printf("[bperf] %sHOGP(average)%s(%ds) Input Report Num (%d)  Max_Delta_Time(%dms)\n",
                            YELLOW, NONECOLOR,
                            bperf_average_total_time,
                            event_counter_summary_hogp/bperf_average_total_time,
                            event_counter_summary_hogp_delta_time_max/1000);
                    event_counter_summary_hogp = 0;
                    event_counter_summary_hogp_delta_time_max = 0;
                }
                if ( event_counter_summary_hogp_cursor )
                {
                    printf("[bperf] %sHOGP_Mouse(average)%s(%ds) Input Report Num (%d)  Max_Delta_Time(%dms)\n",
                            YELLOW, NONECOLOR,
                            bperf_average_total_time,
                            event_counter_summary_hogp_cursor/bperf_average_total_time,
                            event_counter_summary_hogp_cursor_delta_time_max/1000);
                    event_counter_summary_hogp_cursor = 0;
                    event_counter_summary_hogp_cursor_delta_time_max = 0;
                }
                if ( event_len_summary_voice )
                {
                    printf("[bperf] %sVOICE(average)%s(%ds) Voice Data Rate (%d bps)  Total Packet Drop (%d)\n" ,
                            YELLOW, NONECOLOR,
                            bperf_average_total_time, (event_len_summary_voice<<3)/bperf_average_total_time, event_len_summary_voice_drop);
                    event_len_summary_voice = 0;
                    event_len_summary_voice_drop = 0;
                }
                if ( event_len_summary_rc_fw_upgrade )
                {
                    printf("[bperf] %sFW_UPGRADE(average)%s(%ds) Voice Data Rate (%d bps)\n",
                            YELLOW, NONECOLOR,
                            bperf_average_total_time, (event_len_summary_rc_fw_upgrade<<3)/bperf_average_total_time);
                    event_len_summary_rc_fw_upgrade = 0;
                }
            }
            bperf_average_total_time_index = bperf_average_total_time;
        }
        bperf_average_total_time_index--;
    }
}

#ifdef OS_FRTOS
int *_bperf_thread_main(void *arg)
#else
static void *_bperf_thread_main(void *arg)
#endif
{
    unsigned int time_begin;
    unsigned int time_end;
    unsigned int time_sleep;
    (void)arg;
    printf("Thread Started\n");


    bperf_main_thread_status = BPERF_STATE_THREAD_RUNNING;
    while(!bperf_main_thread_should_stop)
    {
        time_begin = _bperf_get_microseconds();

        osi_pthread_mutex_lock(&event_data_lock);
        _bperf_mem_copy();
        _bperf_mem_reset();
        osi_pthread_mutex_unlock(&event_data_lock);

        _bperf_analysis();
        _bperf_mem_reset_analysis();
        time_end = _bperf_get_microseconds();
        time_sleep = 1000000-(time_end-time_begin);
        osi_usleep(time_sleep);
        bperf_global_counter++;
    }

    bperf_main_thread_should_stop = 0;
    bperf_main_thread_status = BPERF_STATE_THREAD_STOPPED;
    printf("Thread Stopped\n");
    return 0;
}

static void _bperf_thread_start()
{
    if ( bperf_main_thread_status != BPERF_STATE_THREAD_RUNNING && !bperf_main_thread_should_stop)
    {
        printf("Create thread\n");
        osi_pthread_create(&bperf_thread_main, NULL, _bperf_thread_main, NULL);
    }
}

static void _bperf_thread_stop()
{
    bperf_main_thread_should_stop = 1;
}

static void _bperf_notify_le_scan(const uint8_t *buf, const unsigned int buf_len)
{
    static unsigned int le_scan_start_time;

    /* HCI_LE_SCAN_ENABLE */
    if ( buf_len == 5 && buf[0] == 0x0c && buf[1] == 0x20 && buf[2] == 0x02 )
    {
        /* HCI_LE_SCAN_ENABLE Started */
        if ( buf[3] == 1 )
        {
            le_scan_start_time = _bperf_get_microseconds();
            printf("[bperf] %sHCI_LE_SCAN_ENABLE%s Started (%sDuplicate_Filter%s:%02x)(0ms)\n",
                    GREEN, NONECOLOR, GREEN, NONECOLOR, buf[4]);
        }
        /* HCI_LE_SCAN_ENABLE Stopped */
        else if ( buf[3] == 0 )
        {
            printf("[bperf] %sHCI_LE_SCAN_ENABLE%s Stopped (Duplicate_Filter:%02x) (Total_Scan_Time:%dms)\n",
                    GREEN, NONECOLOR, buf[4],
                    ((_bperf_get_microseconds()-le_scan_start_time)/1000));
            le_scan_start_time = 0;
        }
    }
    /* HCI_LE_SET_SCAN_PARAMETER */
    else if ( buf_len == 10 && buf[0] == 0x0b && buf[1] == 0x20 && buf[2] == 0x07 )
    {
        float le_scan_interval = (buf[4] + (buf[5]<<8))*0.625;
        float le_scan_window = (buf[6] + (buf[7]<<8))*0.625;

        printf("[bperf] %sHCI_LE_SET_SCAN_PARAMETER%s (%scan_window%s:%.2fms) (%sscan_interval%s:%.2fms)\n",
                GREEN, NONECOLOR, GREEN, NONECOLOR, le_scan_window, GREEN, NONECOLOR, le_scan_interval);
    }
    /* HCI_LE_ADVERTISING_REPORT */
    else
    {
        _bperf_mem_record_event(bperf_event_ble_scan, buf, buf_len);
    }
}

void bperf_notify_cmd(const uint8_t *buf, const unsigned int buf_len)
{
    if ( bperf_main_thread_status == BPERF_STATE_THREAD_RUNNING && !bperf_main_thread_should_stop )
    {
        /* HCI_LE_SCAN_ENABLE */
        if ( buf_len == 5 && buf[0] == 0x0c && buf[1] == 0x20 && buf[2] == 0x02 )
        {
            _bperf_notify_le_scan(buf, buf_len);
        }
        /* HCI_LE_SET_SCAN_PARAMETER */
        else if ( buf_len == 10 && buf[0] == 0x0b && buf[1] == 0x20 && buf[2] == 0x07 )
        {
            _bperf_notify_le_scan(buf, buf_len);
        }
        /* HCI_INQUIRY */
        else if ( buf_len == 8 && buf[0] == 0x01 && buf[1] == 0x04 && buf[2] == 0x05 )
        {
            _bperf_analysis_inquiry(buf, buf_len);
        }
        /* HCI_REMOTE_NAME_REQUEST */
        else if ( buf_len == 13 && buf[0] == 0x19 && buf[1] == 0x04 && buf[2] == 0x0a )
        {
            _bperf_analysis_inquiry(buf, buf_len);
        }
    }
}

void bperf_notify_event(const uint8_t *buf, const unsigned int buf_len)
{
    if ( bperf_main_thread_status == BPERF_STATE_THREAD_RUNNING && !bperf_main_thread_should_stop )
    {
        /* HCI_LE_ADVERTISING_REPORT */
        if ( (buf_len > 12) && buf[0] == 0x3e && buf[2] == 0x02 && buf[3] == 0x01 )
        {
            _bperf_notify_le_scan(buf, buf_len);
        }
        /* HCI_INQUIRY_COMPLETE */
        else if ( buf_len == 3 && buf[0] == 0x01 && buf[1] == 0x01 && buf[2] == 0x00 )
        {
            _bperf_analysis_inquiry(buf, buf_len);
        }
        /* HCI_REMOTE_NAME_REQUEST_COMPLETE */
        else if ( buf[0] == 0x07 && buf[1] == 0xff && buf[2] == 0x00 )
        {
            _bperf_analysis_inquiry(buf, buf_len);
        }
        /* HCI_EXTEND_INQUIRY_RESULT */
        else if ( buf[0] == 0x2f && buf[1] == 0xff && buf[2] == 0x01 )
        {
            _bperf_analysis_inquiry(buf, buf_len);
        }
    }
}

void bperf_notify_acl(const uint8_t *buf, const unsigned int buf_len)
{
    if ( bperf_main_thread_status == BPERF_STATE_THREAD_RUNNING && !bperf_main_thread_should_stop )
    {
        /* A2DP Sink */
        if ( buf[8] == 0x80 && buf[9] == 0x60 )
        {
            _bperf_mem_record_event(bperf_event_a2dp, buf, buf_len);
            if ( buf[20] == 0x00 ) /* SCMS-T */
                bperf_global_bitpool = buf[24];
            else
                bperf_global_bitpool = buf[23];
        }
        /* A2DP Src */
        else if ( buf_len == 587 && buf[8] == 0x80 && buf[9] == 0x60 && buf[20] == 0x00 )
        {
            _bperf_mem_record_event(bperf_event_a2dp, buf, buf_len);
            bperf_global_bitpool = buf[24];
        }
        /* HID_Mouse : Microsoft Sculpt Comfort Mouse */
        else if ( buf_len == 19 && buf[2] == 0x0f && buf[3] == 0x00 && buf[4] == 0x0b && buf[5] == 0x00 && buf[9] == 0x1a )
        {
            _bperf_mem_record_event(bperf_event_hid_cursor, buf, buf_len);
        }
        /* HID_Mouse : Logitech M557 */
        else if ( buf_len == 16 && buf[2] == 0x0c && buf[3] == 0x00 && buf[4] == 0x08 && buf[5] == 0x00 && buf[8] == 0xa1 )
        {
            _bperf_mem_record_event(bperf_event_hid_cursor, buf, buf_len);
        }
        /* HID_Mouse : Logitech M558 */
        else if ( buf_len == 17 && buf[2] == 0x0d && buf[3] == 0x00 && buf[4] == 0x09 && buf[5] == 0x00 && buf[8] == 0xa1 )
        {
            _bperf_mem_record_event(bperf_event_hid_cursor, buf, buf_len);
        }
        /* HOGP_Mouse : Microsoft Designer BLE Mouse*/
        else if ( buf_len == 20 && buf[2] == 0x10 && buf[3] == 0x00 && buf[4] == 0x0c && buf[5] == 0x00 && buf[8] == 0x1b )
        {
            _bperf_mem_record_event(bperf_event_hogp_cursor, buf, buf_len);
        }
        /* HOGP_Mouse : Elecom BLE Mouse */
        else if ( buf_len == 17 && buf[2] == 0x0d && buf[3] == 0x00 && buf[4] == 0x09 && buf[5] == 0x00 && buf[8] == 0x1b )
        {
            _bperf_mem_record_event(bperf_event_hogp_cursor, buf, buf_len);
        }
        /* HID : Logitech Keyboard */
        else if ( buf_len == 18 && buf[2] == 0x0e && buf[3] == 0x00 && buf[4] == 0x0a && buf[5] == 0x00 && buf[8] == 0xa1 )
        {
            _bperf_mem_record_event(bperf_event_hid, buf, buf_len);
        }
        /* HID : SNOW RC */
        else if ( buf_len == 13 && buf[2] == 0x09 && buf[3] == 0x00 && buf[4] == 0x05 && buf[5] == 0x00 && buf[8] == 0xa1 )
        {
            _bperf_mem_record_event(bperf_event_hid, buf, buf_len);
        }
        /* HID : HT RC Button */
        else if ( buf_len == 12 && buf[2] == 0x08 && buf[3] == 0x00 && buf[4] == 0x04 && buf[5] == 0x00 && buf[8] == 0x1b )
        {
            _bperf_mem_record_event(bperf_event_hogp, buf, buf_len);
        }
        /* HID : HT RC Button */
        else if ( buf_len == 13 && buf[2] == 0x09 && buf[3] == 0x00 && buf[4] == 0x05 && buf[5] == 0x00 && buf[8] == 0x1b )
        {
            _bperf_mem_record_event(bperf_event_hogp, buf, buf_len);
        }
        /* GATT : HT RC Voice Search (2541) */
        if ( (buf_len == 12 || buf_len == 31) &&
             (buf[2] == 0x08 || buf[2] == 0x1b) && buf[3] == 0x00 && buf[8] == 0x1b && buf[9] == 0x35 && buf[10] == 0x00 )
        {
            bperf_global_voble_codec = 0;
            _bperf_mem_record_event(bperf_event_voice, buf, buf_len);
        }
        /* GATT : HT RC Voice Search (2640) */
        else if ( buf_len == 31 && buf[2] == 0x1b && buf[3] == 0x00 && buf[8] == 0x1b && buf[9] == 0x3f && buf[10] == 0x00 )
        {
            bperf_global_voble_codec = 0;
            _bperf_mem_record_event(bperf_event_voice, buf, buf_len);
        }
        /* GATT : HT RC Voice Search (2640)(BLE Data Length Extension) */
        else if ( buf_len == 111 && buf[2] == 0x6b && buf[3] == 0x00 && buf[8] == 0x1b && buf[9] == 0x3f && buf[10] == 0x00 )
        {
            bperf_global_voble_codec = 0;
            _bperf_mem_record_event(bperf_event_voice, buf, buf_len);
        }
        /* GATT : Airoha Voice Search */
        else if ( buf_len == 31 && buf[2] == 0x1b && buf[3] == 0x00 && buf[8] == 0x1b && buf[9] == 0x29 && buf[10] == 0x00 )
        {
            bperf_global_voble_codec = 0;
            _bperf_mem_record_event(bperf_event_voice, buf, buf_len);
        }
        /* GATT : Nordic Voice Search, Turnkey */
        else if ( buf[3] == 0x00 && buf[8] == 0x1b && buf[9] == 0x1d && buf[10] == 0x00 )
        {
            bperf_global_voble_codec = 1;
            _bperf_mem_record_event(bperf_event_voice, buf, buf_len);
        }
        /* GATT : Nordic Voice Search, Huitong */
        else if ( buf[3] == 0x00 && buf[8] == 0x1b && buf[9] == 0x23 && buf[10] == 0x00 )
        {
            bperf_global_voble_codec = 1;
            _bperf_mem_record_event(bperf_event_voice, buf, buf_len);
        }

        /* GATT : HT RC FW Upgrade */
        else if ( buf_len == 29 && buf[2] == 0x19 && buf[3] == 0x00 && buf[4] == 0x15 && buf[5] == 0x00 && buf[9] == 0x48 && buf[10] == 0x00 )
        {
            _bperf_mem_record_event(bperf_event_rc_fw_upgrade, buf, buf_len);
        }
#if 0
        /* HID : DS4 */
        else if ( buf_len == 19 && buf[2] == 0x0f && buf[3] == 0x00 && buf[4] == 0x0b && buf[5] == 0x00 && buf[8] == 0xa1 )
        {
            _bperf_mem_record_event(bperf_event_hid, buf, buf_len);
        }
#endif
    }
}

void bperf_set_average_timer(const unsigned int average_timer)
{
    printf("[bperf] average timer length is set to %d secondsd\n", average_timer);
    bperf_average_total_time_index = average_timer;
    bperf_average_total_time = average_timer;
    bperf_average_accumulate = 1;
}

void bperf_init()
{
    printf("[bperf] Version : %s\n", BPERF_LIBRARY_VERSION);
    bperf_global_counter = 0;
    osi_pthread_mutex_init(&event_data_lock, NULL);
    _bperf_thread_start();
    return;
}

void bperf_uninit()
{
    _bperf_thread_stop();
    _bperf_mem_free();
    osi_pthread_mutex_destroy(&event_data_lock);
    return;
}
