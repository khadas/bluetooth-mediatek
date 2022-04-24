ifeq ($(BOARD_BLUETOOTH_DEVICE),mediatek)
LOCAL_PATH := $(call my-dir)

    ifeq ($(BOARD_MTK_ONE_IMAGE),true)
        include $(call all-subdir-makefiles)
    else
        include $(LOCAL_PATH)/$(BOARD_MTK_WLAN_CHIP)/Android.mk
    endif
endif
