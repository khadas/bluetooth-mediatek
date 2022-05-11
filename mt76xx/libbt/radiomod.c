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
 * MediaTek Inc. (C) 2014. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include "bt_hci_bdroid.h"
#include "bt_vendor_lib.h"
#include "bt_mtk.h"

#ifndef  MTK_LINUX
#include <cutils/properties.h>
#endif

/**************************************************************************
 *                  G L O B A L   D E F I N E                             *
***************************************************************************/
#define BT_IDME_MAC_FILE_NAME    "/proc/idme/bt_mac_addr"

/**************************************************************************
 *                  G L O B A L   V A R I A B L E S                       *
***************************************************************************/

BT_INIT_VAR_T btinit[1];
BT_INIT_CB_T  btinit_ctrl;

static uint16_t wOpCode;
static HCI_CMD_STATUS_T cmd_status;
extern bt_vendor_callbacks_t *bt_vnd_cbacks;

static BOOL fgGetEFUSE = FALSE;
static UCHAR ucDefaultAddr[6];
static UCHAR ucZeroAddr[6];

VOID thread_exit(INT32 signo)
{
    pthread_t tid = pthread_self();
    LOG_DBG("Thread %lu is forced to exit...\n", tid);
    if (pthread_mutex_unlock(&btinit_ctrl.mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock error\n");
    }
    pthread_mutexattr_destroy(&btinit_ctrl.attr);
    pthread_mutex_destroy(&btinit_ctrl.mutex);
    pthread_cond_destroy(&btinit_ctrl.cond);
    pthread_exit(0);
}

static VOID HCI_Command_Complete(VOID *p_evt)
{
    HC_BT_HDR *p_buf = (HC_BT_HDR *)p_evt;
    uint8_t *p;
    uint8_t event, status;
    uint16_t opcode;
    BOOL success;

    LOG_DBG("HCI_Command_Complete\n");

    p = (uint8_t *)(p_buf + 1);
    event = *p;
    p += 3;
    STREAM_TO_UINT16(opcode, p);
    status = *p;

    if ((event == 0x0E) && /* Command Complete Event */
        (opcode == wOpCode) && /* OpCode correct */
        (status == 0)) /* Success */
    {
        success = TRUE;
    } else {
        success = FALSE;
    }

    if (bt_vnd_cbacks) {
        bt_vnd_cbacks->dealloc(p_buf);
    }

    pthread_mutex_lock(&btinit_ctrl.mutex);
    cmd_status = success ? CMD_SUCCESS : CMD_FAIL;
    /* Wake up command tx thread */
    pthread_cond_signal(&btinit_ctrl.cond);
    pthread_mutex_unlock(&btinit_ctrl.mutex);

    return;
}

static void idme_get_bt_mac_addr(unsigned char *pucBDAddr)
{
    int bt_idme_file_fd = -1;
    int i;
    char bt_mac_addrs[12] = {0};
    char buf[3] = {0};
    int size = 0;
    LOG_DBG("Get BT addr\n");

    bt_idme_file_fd = open(BT_IDME_MAC_FILE_NAME, O_RDONLY);
    if (bt_idme_file_fd < 0) {
        LOG_ERROR("Open BT addr fails\n");
        return;
    }
    size = read(bt_idme_file_fd, bt_mac_addrs, sizeof(bt_mac_addrs));

    if (size < 0 || size != 12) {
        LOG_ERROR("Read BT addr fails, size:%d\n", size);
        close(bt_idme_file_fd);
        return;
    }
    for (i = 0; i < 12; i += 2) {
        buf[0] = bt_mac_addrs[i];
        buf[1] = bt_mac_addrs[i + 1];
        pucBDAddr[i >> 1] = (unsigned char)strtoul(buf, NULL, 16);
        LOG_DBG("i = %d, addr = %02x", i >> 1, pucBDAddr[i >> 1]);
    }
    close(bt_idme_file_fd);

    LOG_DBG("Get BT addr PASS\n");
}

static bool HCI_Set_Local_BD_Addr(HC_BT_HDR *p_cmd)
{
    int i;
    bool ret = false;
    uint8_t *p;
    unsigned char BD_address[6] = {0};

    wOpCode = HCI_SET_BD_ADDRESS_OP_CODE;
    idme_get_bt_mac_addr(BD_address);  /* Get address from idme */

    p_cmd->len = 9;
    p = (uint8_t *)(p_cmd + 1);
    UINT16_TO_STREAM(p, wOpCode);
    *p++ = 6;

    for (i = 5; i >= 0; i--) {
        *p++ = BD_address[i];
    }
    /* Send command */
    if (bt_vnd_cbacks) {
        ret = bt_vnd_cbacks->xmit_cb(wOpCode, p_cmd, HCI_Command_Complete);
    }
    return ret;
}


VOID *GORM_FW_Init_Thread(VOID *ptr)
{
    INT32 i = 0;
    HC_BT_HDR  *p_buf = NULL;
    bt_vendor_op_result_t ret = BT_VND_OP_RESULT_FAIL;

    LOG_DBG("FW init thread starts\n");

    pthread_mutexattr_init(&btinit_ctrl.attr);
    pthread_mutexattr_settype(&btinit_ctrl.attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&btinit_ctrl.mutex, &btinit_ctrl.attr);
    pthread_cond_init(&btinit_ctrl.cond, NULL);


    p_buf = NULL;

    if (bt_vnd_cbacks) {
        p_buf = (HC_BT_HDR *)bt_vnd_cbacks->alloc(BT_HC_HDR_SIZE + \
                                                         HCI_CMD_MAX_SIZE);
    }
    else {
        LOG_ERROR("No libbt-hci callbacks!\n");
    }

    if (p_buf) {
        p_buf->event = MSG_STACK_TO_HC_HCI_CMD;
        p_buf->offset = 0;
        p_buf->layer_specific = 0;

        cmd_status = CMD_PENDING;

        if (HCI_Set_Local_BD_Addr(p_buf) == FALSE) {
            LOG_ERROR("Send command %d fails\n", i);
            if (bt_vnd_cbacks) {
                 bt_vnd_cbacks->dealloc(p_buf);
            }
            goto exit;
        }
    }
    else {
        LOG_ERROR("Alloc command %d buffer fails\n", i);
        goto exit;
    }

    /* Wait for event returned */
    pthread_mutex_lock(&btinit_ctrl.mutex);
    while (cmd_status == CMD_PENDING) {
        pthread_cond_wait(&btinit_ctrl.cond, &btinit_ctrl.mutex);
    }

    if (cmd_status == CMD_FAIL) {
        LOG_ERROR("The event of command %d error\n", i);
        pthread_mutex_unlock(&btinit_ctrl.mutex);
        goto exit;
    }
    else {
        LOG_DBG("The event of command %d success\n", i);
        pthread_mutex_unlock(&btinit_ctrl.mutex);
    }


    ret = BT_VND_OP_RESULT_SUCCESS;

exit:
    pthread_mutexattr_destroy(&btinit_ctrl.attr);
    pthread_mutex_destroy(&btinit_ctrl.mutex);
    pthread_cond_destroy(&btinit_ctrl.cond);

    if (bt_vnd_cbacks) {
        bt_vnd_cbacks->fwcfg_cb(ret);
    }

    btinit_ctrl.worker_thread_running = FALSE;
    return NULL;
}
