ifeq ($(BOARD_BLUETOOTH_DEVICE),mediatek)
LOCAL_PATH := $(call my-dir)

include $(LOCAL_PATH)/$(BOARD_MTK_WLAN_CHIP)/Android.mk

endif
