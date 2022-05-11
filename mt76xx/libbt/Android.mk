LOCAL_PATH := $(call my-dir)
#$(call config-custom-folder,custom:hal/bluetooth)

###########################################################################
# MTK BT CHIP INIT LIBRARY FOR BLUEDROID
###########################################################################
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  mtk.c \
  radiomgr.c \
  radiomod.c

LOCAL_C_INCLUDES := \
  device/mstar/common/libraries/bluetooth/mediatek/libdriver \
  system/bt/hci/include \

LOCAL_CFLAGS += -DMTK_MT7662


ifeq ($(TARGET_BUILD_VARIANT), eng)
LOCAL_CFLAGS += -DBD_ADDR_AUTOGEN
endif

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libbluetooth_mtk
LOCAL_SHARED_LIBRARIES := liblog libcutils
LOCAL_PRELINK_MODULE := false
include $(BUILD_SHARED_LIBRARY)

###########################################################################
# MTK BT DRIVER FOR BLUEDROID
###########################################################################
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  bt_drv.c

LOCAL_C_INCLUDES := \
  device/mstar/common/libraries/bluetooth/mediatek/libdriver \
  system/bt/hci/include \

LOCAL_CFLAGS := -DMTK_BLUEDROID_PATCH=TRUE
LOCAL_CFLAGS += -D__UPSTREAM_PASS_HCI_CMD_EVENT_T0_VENDOR_LIBRARY__

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libbt-vendor
LOCAL_SHARED_LIBRARIES := liblog libbluetooth_mtk
LOCAL_PRELINK_MODULE := false
include $(BUILD_SHARED_LIBRARY)

#include $(CLEAR_VARS)
#LOCAL_MODULE := bt_stack.conf
#LOCAL_MODULE_CLASS := ETC
#LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/bluetooth
#LOCAL_MODULE_TAGS := optional
#LOCAL_SRC_FILES :=  $(LOCAL_MODULE)
#include $(BUILD_PREBUILT)

#include $(CLEAR_VARS)
#LOCAL_MODULE := platform.xml
#LOCAL_MODULE_CLASS := ETC
#LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/permissions
#LOCAL_MODULE_TAGS := optional
#LOCAL_SRC_FILES :=  $(LOCAL_MODULE)
#include $(BUILD_PREBUILT)
