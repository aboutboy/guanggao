LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE:= webad

LOCAL_SRC_FILES := \
    main.c \
    libipq.c \
    mpool.c \
    msocket.c \
    plug.c \
    queue.c \
    thpool.c \
    util.c

LOCAL_LDLIBS = -lpthread
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libc

include $(BUILD_EXECUTABLE)
