/*
 *  Copyright (c) 2016 MediaTek Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */
#ifndef __BTMTK_DEFINE_H__
#define __BTMTK_DEFINE_H__

#include "btmtk_config.h"

/**
 * Type definition
 */
#ifndef TRUE
	#define TRUE 1
#endif
#ifndef FALSE
	#define FALSE 0
#endif

#ifndef UNUSED
	#define UNUSED(x) (void)(x)
#endif

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/**
 * Log level definition
 */
#define BTMTK_LOG_LEVEL_ERROR		1
#define BTMTK_LOG_LEVEL_WARNING		2
#define BTMTK_LOG_LEVEL_INFO		3
#define BTMTK_LOG_LEVEL_DEBUG		4
#define BTMTK_LOG_LEVEL_MAX		BTMTK_LOG_LEVEL_DEBUG
#define BTMTK_LOG_LEVEL_DEFAULT		BTMTK_LOG_LEVEL_INFO	/* default setting */

extern u8 btmtk_log_lvl;

#define BTUSB_ERR(fmt, ...)	 \
	do { if (btmtk_log_lvl >= BTMTK_LOG_LEVEL_ERROR) pr_warn_ratelimited("[btmtk_err] "fmt"\n", ##__VA_ARGS__); } while (0)
#define BTUSB_WARN(fmt, ...)	\
	do { if (btmtk_log_lvl >= BTMTK_LOG_LEVEL_WARNING) pr_warn_ratelimited("[btmtk_warn] "fmt"\n", ##__VA_ARGS__); } while (0)
#define BTUSB_INFO(fmt, ...)	\
	do { if (btmtk_log_lvl >= BTMTK_LOG_LEVEL_INFO) pr_warn_ratelimited("[btmtk_info] "fmt"\n", ##__VA_ARGS__); } while (0)
#define BTUSB_DBG(fmt, ...)	 \
	do { if (btmtk_log_lvl >= BTMTK_LOG_LEVEL_DEBUG) pr_warn_ratelimited("[btmtk_debug] "fmt"\n", ##__VA_ARGS__); } while (0)

#define BTUSB_WARN_LIMITTED(fmt, ...)     \
        do {printk_ratelimited(KERN_WARNING     \
            "[btusb_warm_limit] "fmt"\n", ##__VA_ARGS__); } while (0)

#define BTUSB_INFO_RAW(p, l, fmt, ...)							\
		do {									\
			if (btmtk_log_lvl >= BTMTK_LOG_LEVEL_INFO) {			\
				int raw_count = 0;					\
				const unsigned char *ptr = p;				\
				pr_cont("[btmtk_info] "fmt, ##__VA_ARGS__);		\
				for (raw_count = 0; raw_count < l; ++raw_count) {	\
					pr_cont(" %02X", ptr[raw_count]);		\
				}							\
				pr_cont("\n");						\
			}								\
		} while (0)

#define BTUSB_DBG_RAW(p, l, fmt, ...)						\
	do {									\
		if (btmtk_log_lvl >= BTMTK_LOG_LEVEL_DEBUG) {			\
			int raw_count = 0;					\
			const unsigned char *ptr = p;				\
			pr_cont("[btmtk_debug] "fmt, ##__VA_ARGS__);		\
			for (raw_count = 0; raw_count < l; ++raw_count) {	\
				pr_cont(" %02X", ptr[raw_count]);		\
			}							\
			pr_cont("\n");						\
		}								\
	} while (0)

/**
 * Log file path & name, the default path is /sdcard
 */
#define SYSLOG_FNAME			"bt_sys_log"
#define FWDUMP_FNAME			"bt_fw_dump"
#ifdef BTMTK_LOG_PATH
	#define SYS_LOG_FILE_NAME	(BTMTK_LOG_PATH SYSLOG_FNAME)
	#define FW_DUMP_FILE_NAME	(BTMTK_LOG_PATH FWDUMP_FNAME)
#else
	#define SYS_LOG_FILE_NAME	"/sdcard/"SYSLOG_FNAME
	#define FW_DUMP_FILE_NAME	"/sdcard/"FWDUMP_FNAME
#endif /* FW_DUMP_FILE_NAME */

/**
 * Monitor Chip reset
 */
#define RESET_BT	"RESET_BT\n"		/* echo RESET_BT > /dev/stpbtfwlog */
#define RESET_BT_DONE	"RESET_BT_DONE\n"	/* Return this if reset successful in 5 sec */
#define RESET_BT_TIMO	"RESET_BT_TIMO\n"	/* Return this if reset failed in 5 sec */
#define RESET_TIMO	8			/* Timeout/seconds */

/**
 *Moniter FW dump
 */
#define FW_DUMP_TIMO	20		/* Timeout/seconds */

/**
 * SYS control
 */
#define SYSCTL	0x400000

/**
 * WLAN
 */
#define WLAN	0x410000

/**
 * MCUCTL
 */
#define CLOCK_CTL	0x0708
#define INT_LEVEL	0x0718
#define COM_REG0	0x0730
#define SEMAPHORE_00	0x07B0
#define SEMAPHORE_01	0x07B4
#define SEMAPHORE_02	0x07B8
#define SEMAPHORE_03	0x07BC

/**
 * Timeout setting, mescs
 */
#ifdef USB_IO_TIMO
	#define USB_CTRL_IO_TIMO	USB_IO_TIMO
#else
	#define USB_CTRL_IO_TIMO	100
#endif
#ifdef WAIT_EVENT_TIMO
	#define USB_INTR_MSG_TIMO	WAIT_EVENT_TIMO
#else
	#define USB_INTR_MSG_TIMO	2000
#endif

#ifdef WOBLE_MULTI_EVENT_INT_TIMO
	#define WOBLE_EVENT_INTERVAL_TIMO	WOBLE_MULTI_EVENT_INT_TIMO
#else
	#define WOBLE_EVENT_INTERVAL_TIMO	500
#endif
#define WOBLE_COMP_EVENT_TIMO		5000

/**
 * For chip reset pin
 */
#define RESET_PIN_SET_LOW_TIME		50

/**
 * USB request type definition
 */
#define DEVICE_VENDOR_REQUEST_OUT	0x40
#define DEVICE_VENDOR_REQUEST_IN	0xc0
#define DEVICE_CLASS_REQUEST_OUT	0x20
#define DEVICE_CLASS_REQUEST_IN		0xa0

#define BTUSB_MAX_ISOC_FRAMES	15
#define BTUSB_INTR_RUNNING	0
#define BTUSB_BULK_RUNNING	1
#define BTUSB_ISOC_RUNNING	2
#define BTUSB_SUSPENDING	3
#define BTUSB_DID_ISO_RESUME	4

/**
 * ROM patch related
 */
#define PATCH_HCI_HEADER_SIZE	4
#define PATCH_WMT_HEADER_SIZE	5
#define PATCH_HEADER_SIZE	(PATCH_HCI_HEADER_SIZE + PATCH_WMT_HEADER_SIZE)
#define UPLOAD_PATCH_UNIT	2048
#define PATCH_INFO_SIZE		30
#define PATCH_PHASE1		1
#define PATCH_PHASE2		2
#define PATCH_PHASE3		3
#define PATCH_LEN_ILM		(192 * 1024)

#define META_BUFFER_SIZE	(1024 * 500)
#define USB_IO_BUF_SIZE		(HCI_MAX_EVENT_SIZE > 256 ? HCI_MAX_EVENT_SIZE : 256)
#ifndef HCI_SNOOP_ENTRY_NUM
#define HCI_SNOOP_ENTRY_NUM	30
#endif
#define HCI_SNOOP_BUF_SIZE	32
#define FW_VERSION_SIZE		15 /* 14 bytes for FW version + 1 byte for end */
#define FW_VERSION_BUF_SIZE	32

#define FW_QUEUE_FULL_ERR_MAX_TIMES	100

/**
 * stpbtfwlog device node
 */
#define HCI_MAX_COMMAND_SIZE		255

/**
 * Write a char to buffer.
 * ex : echo 01 be > /dev/stpbtfwlog
 * "01 " need three bytes.
 */
#define HCI_MAX_COMMAND_BUF_SIZE	(HCI_MAX_COMMAND_SIZE * 3)

/**
 * HCI CMD/ACL/SCO Header length
 */
#define HCI_CMD_HEADER_LEN	(4)
#define HCI_ACL_HEADER_LEN	(5)
#define HCI_SCO_HEADER_LEN	(4)

/**
 * stpbt device node
 */
#define BUFFER_SIZE		(1024 * 4)	/* Size of RX Queue */
#define IOC_MAGIC		0xb0
#define IOCTL_FW_ASSERT		_IOWR(IOC_MAGIC, 0, void *)
#define IOCTL_SET_ISOC_IF_ALT	_IOWR(IOC_MAGIC, 1, int)	/* Set interface & alternate */

/**
 * fw log queue count
 */
#define FWLOG_QUEUE_COUNT			200
#define FWLOG_BLUETOOTH_KPI_QUEUE_COUNT		200
#define FWLOG_ASSERT_QUEUE_COUNT		6000

/**
 * Maximum rom patch file name length
 */
#define MAX_BIN_FILE_NAME_LEN 32

/**
 * GPIO PIN configureation
 */
#ifndef BT_DONGLE_RESET_GPIO_PIN
	#define BT_DONGLE_RESET_GPIO_PIN	220
#endif /* BT_DONGLE_RESET_GPIO_PIN */

/**
 * WoBLE by BLE RC
 */
#ifndef SUPPORT_LEGACY_WOBLE
	#define SUPPORT_LEGACY_WOBLE 0
	#define BT_RC_VENDOR_DEFAULT 1
	#define BT_RC_VENDOR_S0 0
#endif

/**
 * Disable RESUME_RESUME
 */
#ifndef BT_DISABLE_RESET_RESUME
	#define BT_DISABLE_RESET_RESUME 0
#endif

#define WOBLE_SETTING_FILE_NAME "woble_setting.bin"
#define IR_PROTOCOL		"IR_PROTO"
#define IR_KEYMAP_G		"IR_KEYMAP_GROUP"
#define IR_KEYMAP		"IR_KEYMAP"
#define MAX_IRKMG		20 /* Max IR keymap group, MUST sync with FW */
#define WOBLE_SETTING_COUNT 10

#define WOBLE_FAIL -10

#define WOBX_TYPE_IR			0x11	/* radio cmd, attr type */
#define WOBX_TYPE_KEYCODE_MAPPING	0x47	/* radio cmd, attr type */

#define PRINT_DUMP_PACKET_COUNT 20

#endif /* __BTMTK_DEFINE_H__ */
