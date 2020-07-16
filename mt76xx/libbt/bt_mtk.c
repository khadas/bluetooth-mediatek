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
#include <string.h>
#include <fcntl.h>
#include <cutils/properties.h>

#include "bt_mtk.h"

/**************************************************************************
 *                  G L O B A L   V A R I A B L E S                       *
***************************************************************************/

bt_vendor_callbacks_t *bt_vnd_cbacks = NULL;
static int  bt_fd = -1;

/**************************************************************************
 *              F U N C T I O N   D E C L A R A T I O N S                 *
***************************************************************************/

extern BOOL BT_InitDevice(
    UINT32  chipId,
    PUCHAR  pucNvRamData,
    UINT32  u4Baud,
    UINT32  u4HostBaud,
    UINT32  u4FlowControl,
    SETUP_UART_PARAM_T setup_uart_param
);

extern BOOL BT_InitSCO(VOID);
extern BOOL BT_DeinitDevice(VOID);
extern VOID BT_Cleanup(VOID);

/**************************************************************************
 *                          F U N C T I O N S                             *
***************************************************************************/
/* Register callback functions to libbt-hci.so */
void set_callbacks(const bt_vendor_callbacks_t *p_cb)
{
    bt_vnd_cbacks = (bt_vendor_callbacks_t *)p_cb;
}

/* Cleanup callback functions previously registered */
void clean_callbacks(void)
{
    bt_vnd_cbacks = NULL;
}

/* Initialize UART port */
int init_uart(void)
{
    LOG_TRC();
    if (bt_fd >= 0) {
        LOG_WAN("Previous serial port is not closed\n");
        close_uart();
    }

    bt_fd = open("/dev/stpbt", O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (bt_fd < 0) {
        LOG_ERR("Can't open serial port!!!");
        return -1;
    }

    return bt_fd;
}

/* Close UART port previously opened */
void close_uart(void)
{
    if (bt_fd >= 0) close(bt_fd);
    bt_fd = -1;
}

static int bt_get_combo_id(unsigned int *pChipId)
{
    int  chipId_ready_retry = 0;
    char chipId_val[PROPERTY_VALUE_MAX];

    do {
        if (property_get("persist.mtk.wcn.combo.chipid", chipId_val, NULL) &&
            0 != strcmp(chipId_val, "-1")) {
            *pChipId = (unsigned int)strtoul(chipId_val, NULL, 16);
            break;
        }
        else {
            chipId_ready_retry ++;
            usleep(500000);
        }
    } while(chipId_ready_retry < 10);

    LOG_DBG("Get combo chip id retry %d\n", chipId_ready_retry);
    if (chipId_ready_retry >= 10) {
        LOG_DBG("Invalid combo chip id!\n");
        return -1;
    }
    else {
        LOG_DBG("Combo chip id %x\n", *pChipId);
        return 0;
    }
}

/** callback function for xmit_cb() */
static VOID xmit_complete_cb(VOID *p_evt)
{
#define HCE_COMMAND_COMPLETE 0x0E
    HC_BT_HDR *p_buf = (HC_BT_HDR *)p_evt;
    uint8_t event = 0;
    uint8_t len = 0;
    uint16_t opcode = 0;
    uint8_t status = 0;

    if (p_buf == NULL) {
        LOG_ERR("Incorrect parameter - p_evt!!!");
        return;
    }

    LOG_TRC();
    if (p_buf->data[0] != HCE_COMMAND_COMPLETE) {
        int i = 0;

        for (i = 0; i < p_buf->len; i++)
            LOG_WAN("p_buf[%d] = %02X", i, p_buf->data[i]);
        return;
    }

    // Expect this is command complete event
    event = p_buf->data[0];
    len = p_buf->data[1];
    opcode = *(uint16_t *)&p_buf->data[3];
    status = p_buf->data[5];
    LOG_DBG("Command_Complete OPCode: %04X, LEN: %02X, Status: %02X",
            opcode, len, status);
    return;
}

/** Set Bluetooth local address */
static bool bd_set_local_bdaddr(uint8_t *addr)
{
#define OPCODE_LEN 2
#define PARAM_SIZE_LEN 1
#define BD_ADDR_LEN 6
    uint16_t opcode = HCI_SET_BD_ADDRESS_OP_CODE;
    HC_BT_HDR *p_buf = NULL;
    uint8_t *p = NULL;
    int i = 0;

    if (bt_vnd_cbacks == NULL) {
        LOG_ERR("No HIDL interface callbacks!!!");
        return false;
    }
    if (addr == NULL) {
        LOG_ERR("No BD address!!!");
        return false;
    }
    LOG_TRC();

    p_buf = (HC_BT_HDR *)bt_vnd_cbacks->alloc(BT_HC_HDR_SIZE + OPCODE_LEN
            + PARAM_SIZE_LEN + BD_ADDR_LEN);
    if (p_buf == NULL) {
        LOG_ERR("Allocation fail!!!");
        return false;
    }

    p_buf->event = MSG_STACK_TO_HC_HCI_CMD;
    p_buf->len = OPCODE_LEN + PARAM_SIZE_LEN + BD_ADDR_LEN;
    p_buf->offset = 0;
    p_buf->layer_specific = 0;

    p = (uint8_t *)(p_buf + 1);
    memcpy(p, &opcode, OPCODE_LEN); // opcode
    p += 2;
    *p++ = 6; // len

/**
 * The "string_to_bytes()" from HIDL HAL actually reverted
 * the byte ordering in the output "addr" array, so we need
 * to revert it back!
 */

    *p++ = addr[5];
    *p++ = addr[4];
    *p++ = addr[3];
    *p++ = addr[2];
    *p++ = addr[1];
    *p++ = addr[0];

    LOG_DBG("CMD: %02X %02X %02X %02X %02X %02X %02X %02X : %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            *(uint8_t *)p_buf, *(((uint8_t *)p_buf) + 1),           // event
            *(((uint8_t *)p_buf) + 2), *(((uint8_t *)p_buf) + 3),   // len
            *(((uint8_t *)p_buf) + 4), *(((uint8_t *)p_buf) + 5),   // offset
            *(((uint8_t *)p_buf) + 6), *(((uint8_t *)p_buf) + 7),   // layer_specific
            // following are data
            *(((uint8_t *)p_buf) + 8), *(((uint8_t *)p_buf) + 9), *(((uint8_t *)p_buf) + 10),
            *(((uint8_t *)p_buf) + 11), *(((uint8_t *)p_buf) + 12), *(((uint8_t *)p_buf) + 13),
            *(((uint8_t *)p_buf) + 14), *(((uint8_t *)p_buf) + 15), *(((uint8_t *)p_buf) + 16));

    bt_vnd_cbacks->xmit_cb(opcode, p_buf, xmit_complete_cb);
    // p_buf will free by xmit_cb.
    return true;
}

/* MTK specific chip initialize process */
int mtk_fw_cfg(uint8_t *bdaddr)
{
    unsigned int chipId = 0x7662;
    unsigned char ucNvRamData[64] = {0};
    unsigned int speed = 0, flow_control = 0;
    SETUP_UART_PARAM_T uart_setup_callback = NULL;

    LOG_TRC();
    // Write local address to controller, that get from BT init function
    bd_set_local_bdaddr(bdaddr);

    LOG_WAN("[BDAddr %02x-%02x-%02x-%02x-%02x-%02x][Voice %02x %02x][Codec %02x %02x %02x %02x]\n\
            [Radio %02x %02x %02x %02x %02x %02x][Sleep %02x %02x %02x %02x %02x %02x %02x][BtFTR %02x %02x]\n\
            [TxPWOffset %02x %02x %02x][CoexAdjust %02x %02x %02x %02x %02x %02x]\n",
            ucNvRamData[0], ucNvRamData[1], ucNvRamData[2], ucNvRamData[3], ucNvRamData[4], ucNvRamData[5],
            ucNvRamData[6], ucNvRamData[7],
            ucNvRamData[8], ucNvRamData[9], ucNvRamData[10], ucNvRamData[11],
            ucNvRamData[12], ucNvRamData[13], ucNvRamData[14], ucNvRamData[15], ucNvRamData[16], ucNvRamData[17],
            ucNvRamData[18], ucNvRamData[19], ucNvRamData[20], ucNvRamData[21], ucNvRamData[22], ucNvRamData[23], ucNvRamData[24],
            ucNvRamData[25], ucNvRamData[26],
            ucNvRamData[27], ucNvRamData[28], ucNvRamData[29],
            ucNvRamData[30], ucNvRamData[31], ucNvRamData[32], ucNvRamData[33], ucNvRamData[34], ucNvRamData[35]);

    return (BT_InitDevice(
              chipId,
              ucNvRamData,
              speed,
              speed,
              flow_control,
              uart_setup_callback) == TRUE ? 0 : -1);
}

/* MTK specific SCO/PCM configuration */
int mtk_sco_cfg(void)
{
    return (BT_InitSCO() == TRUE ? 0 : -1);
}

/* MTK specific deinitialize process */
int mtk_prepare_off(void)
{
    /*
    * On KK, BlueDroid adds BT_VND_OP_EPILOG procedure when BT disable:
    *   - 1. BT_VND_OP_EPILOG;
    *   - 2. In vendor epilog_cb, send EXIT event to bt_hc_worker_thread;
    *   - 3. Wait for bt_hc_worker_thread exit;
    *   - 4. userial close;
    *   - 5. vendor cleanup;
    *   - 6. Set power off.
    * On L, the disable flow is modified as below:
    *   - 1. userial Rx thread exit;
    *   - 2. BT_VND_OP_EPILOG;
    *   - 3. Write reactor->event_fd to trigger bt_hc_worker_thread exit
    *        (not wait to vendor epilog_cb and do nothing in epilog_cb);
    *   - 4. Wait for bt_hc_worker_thread exit;
    *   - 5. userial close;
    *   - 6. Set power off;
    *   - 7. vendor cleanup.
    *
    * It seems BlueDroid does not expect Tx/Rx interaction with chip during
    * BT_VND_OP_EPILOG procedure, and also does not need to do it in a new
    * thread context (NE may occur in __pthread_start if bt_hc_worker_thread
    * has already exited).
    * So BT_VND_OP_EPILOG procedure may be not for chip deinitialization,
    * do nothing, just notify success.
    *
    * [FIXME!!]How to do if chip deinit is needed?
    */
    //return (BT_DeinitDevice() == TRUE ? 0 : -1);
    if (bt_vnd_cbacks) {
        bt_vnd_cbacks->epilog_cb(BT_VND_OP_RESULT_SUCCESS);
    }
    return 0;
}

/* Cleanup driver resources, e.g thread exit */
void clean_resource(void)
{
    BT_Cleanup();
}
