LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

CAL_CFLAGS := -Wall-ansi

LOCAL_SRC_FILES := bperf_util.c common.c osi_linux.c picus_main.c

#LOCAL_STATIC_LIBRARIES := libc
#LOCAL_FORCE_STATIC_EXECUTABLE := true

LOCAL_MODULE:= picus
LOCAL_MODULE_TAGS := optional
LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE_OWNER := mtk
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)

