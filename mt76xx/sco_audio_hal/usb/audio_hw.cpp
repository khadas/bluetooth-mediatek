/*
/ * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// fosmod_audio_tv newfile

#define LOG_TAG "audio_sco_hw"
//#define LOG_NDEBUG 0

#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cutils/log.h>
#include <cutils/properties.h>
#include <utils/String8.h>
#include <cstdlib>
#include <cstring>

#include <hardware/hardware.h>
#include <system/audio.h>
#include <hardware/audio.h>
#include <media/AudioParameter.h>
#include "amazon_remotes.h"

#define SCO_DEV     "/dev/stpbt_sco"
#define DEF_CONTENT_LEN 96
#define DEF_PACKET_NUM  5   // One packet is 99 bytes, need takes 3ms

static int bt_socket = -1;
uint64_t time_read_max_delta;
uint64_t time_poll_max_delta;

android::String8 mSearchSourceVid;
android::String8 mSearchSourcePid;
android::String8 mSearchSourceSerial;

using namespace android;

struct sco_audio_device {
    struct audio_hw_device device;
};
struct sco_audio_device *adev = NULL;

struct sco_stream_out {
    struct audio_stream_out stream;
    int64_t last_write_time_us;
};

struct sco_stream_in {
    struct audio_stream_in stream;
    pthread_t tx_id;
    pthread_mutex_t lock;
    bool standby;
    int counter_size;
    int counter_iteration;
    uint64_t time_iteration_begin;
    uint64_t time_last;
    uint64_t time_delta;
    uint64_t time_max_delta;
    bool dump_enabled;
    FILE* dump_fp;
};

static uint64_t GetTickCount()
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);   // ms
}


void* tx_thread(void *stream)
{
    struct sco_stream_in *in = (struct sco_stream_in *)stream;
    // Generate MUTE pcm data to controller
    int fd = -1;
    ssize_t ret = 0;
    uint32_t seq = 0;
    uint32_t t_sent = 0;
    uint32_t i = 0, j = 0;
    uint8_t buf[DEF_CONTENT_LEN * DEF_PACKET_NUM] = {0}; // every 99 bytes takes 3ms
    uint8_t no_wait_count = 5;

    // every 96 bytes need 3 bytes header
    // fill 0x11, 0x22, 0x33 to each 99 bytes packet content
    for (i = 0; i < sizeof(buf) / DEF_CONTENT_LEN; i++)
        memset(buf + i * DEF_CONTENT_LEN, 0x11 * (i + 1), DEF_CONTENT_LEN);

    do {
        t_sent = GetTickCount();
        /* Add sequence number to each 33 bytes packet */
        for (i = 0; i < 5; i++) {
            *(uint32_t *)(buf + i * 96) = seq;
            if (seq == 0xFFFFFFFF) seq = 0;
            else seq++;
            for (j = 0; j < 2; j++) {
                *(uint32_t *)(buf + i * 96 + j * 33 + 30) = seq;
                if (seq == 0xFFFFFFFF) seq = 0;
                else seq++;
            }
        }
        ret = write(bt_socket, buf, sizeof(buf));

        if (ret != sizeof(buf)) {
            no_wait_count = 5;
        }

        if (ret == sizeof(buf) && no_wait_count > 0) {
            no_wait_count--;
            continue;
        }

        if (GetTickCount() - t_sent >= DEF_PACKET_NUM * 3)
            continue;
        else
            usleep((DEF_PACKET_NUM * 3 - (GetTickCount() - t_sent)) * 1000);
    } while (!in->standby);
    ALOGV("%s End", __func__);
    return NULL;
}



static uint32_t out_get_sample_rate(const struct audio_stream *stream)
{
    return 44100;
}

static int out_set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
    return -ENOSYS;
}

static size_t out_get_buffer_size(const struct audio_stream *stream)
{
    return 4096;
}

static audio_channel_mask_t out_get_channels(const struct audio_stream *stream)
{
    return AUDIO_CHANNEL_OUT_STEREO;
}

static audio_format_t out_get_format(const struct audio_stream *stream)
{
    return AUDIO_FORMAT_PCM_16_BIT;
}

static int out_set_format(struct audio_stream *stream, audio_format_t format)
{
    return -ENOSYS;
}

static int out_standby(struct audio_stream *stream)
{
    // out->last_write_time_us = 0; unnecessary as a stale write time has same effect
    return 0;
}

static int out_dump(const struct audio_stream *stream, int fd)
{
    return 0;
}

static int out_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
    return 0;
}

static char * out_get_parameters(const struct audio_stream *stream, const char *keys)
{
    return strdup("");
}

static uint32_t out_get_latency(const struct audio_stream_out *stream)
{
    return 0;
}

static int out_set_volume(struct audio_stream_out *stream, float left,
                          float right)
{
    return 0;
}

static ssize_t out_write(struct audio_stream_out *stream, const void* buffer,
                         size_t bytes)
{

    ALOGV("out_write: bytes: %d", bytes);

    /* XXX: fake timing for audio output */
    struct sco_stream_out *out = (struct sco_stream_out *)stream;
    struct timespec t = { .tv_sec = 0, .tv_nsec = 0 };
    clock_gettime(CLOCK_MONOTONIC, &t);
    const int64_t now = (t.tv_sec * 1000000000LL + t.tv_nsec) / 1000;
    const int64_t elapsed_time_since_last_write = now - out->last_write_time_us;
    int64_t sleep_time = bytes * 1000000LL / audio_stream_out_frame_size(stream) /
               out_get_sample_rate(&stream->common) - elapsed_time_since_last_write;
    if (sleep_time > 0) {
        usleep(sleep_time);
    } else {
        // we don't sleep when we exit standby (this is typical for a real alsa buffer).
        sleep_time = 0;
    }
    out->last_write_time_us = now + sleep_time;
    // last_write_time_us is an approximation of when the (simulated) alsa
    // buffer is believed completely full. The usleep above waits for more space
    // in the buffer, but by the end of the sleep the buffer is considered
    // topped-off.
    //
    // On the subsequent out_write(), we measure the elapsed time spent in
    // the mixer. This is subtracted from the sleep estimate based on frames,
    // thereby accounting for drain in the alsa buffer during mixing.
    // This is a crude approximation; we don't handle underruns precisely.
    return bytes;
}

static int out_get_render_position(const struct audio_stream_out *stream,
                                   uint32_t *dsp_frames)
{
    *dsp_frames = 0;
    ALOGV("out_get_render_position: dsp_frames: %p", dsp_frames);
    return -EINVAL;
}

static int out_add_audio_effect(const struct audio_stream *stream, effect_handle_t effect)
{
    return 0;
}

static int out_remove_audio_effect(const struct audio_stream *stream, effect_handle_t effect)
{
    return 0;
}

static int out_get_next_write_timestamp(const struct audio_stream_out *stream,
                                        int64_t *timestamp)
{
    *timestamp = 0;
    ALOGV("out_get_next_write_timestamp: %ld", (long int)(*timestamp));
    return -EINVAL;
}

/** audio_stream_in implementation **/
static uint32_t in_get_sample_rate(const struct audio_stream *stream)
{
    return 16000;
}

static int in_set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
    return -ENOSYS;
}

static size_t in_get_buffer_size(const struct audio_stream *stream)
{
    return 480;
}

static audio_channel_mask_t in_get_channels(const struct audio_stream *stream)
{
    return AUDIO_CHANNEL_IN_MONO;
}

static audio_format_t in_get_format(const struct audio_stream *stream)
{
    return AUDIO_FORMAT_PCM_16_BIT;
}

static int in_set_format(struct audio_stream *stream, audio_format_t format)
{
    return -ENOSYS;
}

static int in_standby(struct audio_stream *stream)
{
    struct sco_stream_in *in = (struct sco_stream_in *)stream;
    pthread_mutex_lock(&in->lock);
    in->standby = true;
    pthread_join(in->tx_id, NULL);
    pthread_mutex_unlock(&in->lock);
    return 0;
}

static int in_dump(const struct audio_stream *stream, int fd)
{
    return 0;
}

static int in_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
    return 0;
}

static char * in_get_parameters(const struct audio_stream *stream,
                                const char *keys)
{
    return strdup("");
}

static int in_set_gain(struct audio_stream_in *stream, float gain)
{
    return 0;
}

static ssize_t in_read(struct audio_stream_in *stream, void* buffer,
                       size_t bytes)
{
    ALOGV("in_read: bytes %d", bytes);
    struct sco_stream_in *in = (struct sco_stream_in *)stream;
    ssize_t bytes_read = 0;
    fd_set readfs;
    uint64_t time_read_delta;
    uint64_t time_poll_delta;
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 30000; // 30 ms

    // connect to stpbt_sco
    if (bt_socket < 0) {
        bt_socket = open(SCO_DEV, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (bt_socket < 0) {
            ALOGE("Open %s fail(%d), error:%d", SCO_DEV, bt_socket, errno);
            return -1;
        }
        ALOGV("%s opened(%d)", SCO_DEV, bt_socket);
    }

    pthread_mutex_lock(&in->lock);
    if (in->standby) {
        in->standby = false;
        pthread_create(&in->tx_id, NULL, tx_thread, (void *)in);
    }
    pthread_mutex_unlock(&in->lock);

    if (in->dump_enabled && !in->dump_fp) {
        in->dump_fp = fopen ("/tmp/media/sco_input.pcm", "wb");
        if (!in->dump_fp)
            ALOGE("dump file open fail");
    }

    FD_ZERO(&readfs);
    FD_SET(bt_socket, &readfs);

    time_poll_delta = GetTickCount();
    if (select(bt_socket + 1, &readfs, NULL, NULL, &timeout) > 0) {
        if (FD_ISSET(bt_socket, &readfs)) {
            // Read sco data
            time_poll_delta = GetTickCount() - time_poll_delta;
            if (time_poll_delta > time_poll_max_delta) {
                time_poll_max_delta = time_poll_delta;
            }
            time_read_delta = GetTickCount();
            bytes_read = read(bt_socket, buffer, bytes);
            time_read_delta = GetTickCount() - time_read_delta;
            if (time_read_delta > time_read_max_delta) {
                time_read_max_delta = time_read_delta;
            }

            // Analysis timing
            in->time_delta = GetTickCount() - in->time_last;
            if (in->time_delta > in->time_max_delta) {
                in->time_max_delta = in->time_delta;
            }
            in->time_last = GetTickCount();

            in->counter_size += bytes_read;
            if (in->counter_iteration++ == 65) {
                ALOGD("read size : %d Bytes in %d ms (max delta time is %d ms)\n",
                            in->counter_size,
                            (int)(GetTickCount() - in->time_iteration_begin),
                            (int)in->time_max_delta);
                ALOGD("poll delta time = %d ms, read delta time = %d\n",
                            (int)time_poll_max_delta,
                            (int)time_read_max_delta);
                time_poll_max_delta = 0;
                time_read_max_delta = 0;
                in->counter_iteration = 0;
                in->counter_size = 0;
                in->time_max_delta = 0;
                in->time_iteration_begin = GetTickCount();
            }
        }
    }
    ALOGV("in_read: bytes_read %d", bytes_read);
    if (in->dump_enabled && in->dump_fp) {
        fwrite(buffer, 1, bytes_read, in->dump_fp);
    }
    return bytes_read;
}

static uint32_t in_get_input_frames_lost(struct audio_stream_in *stream)
{
    return 0;
}

static int in_add_audio_effect(const struct audio_stream *stream, effect_handle_t effect)
{
    return 0;
}

static int in_remove_audio_effect(const struct audio_stream *stream, effect_handle_t effect)
{
    return 0;
}

static int adev_open_output_stream(struct audio_hw_device *dev,
                                   audio_io_handle_t handle,
                                   audio_devices_t devices,
                                   audio_output_flags_t flags,
                                   struct audio_config *config,
                                   struct audio_stream_out **stream_out,
                                   const char *address __unused)
{
    ALOGV("adev_open_output_stream...");

    struct sco_audio_device *ladev = (struct sco_audio_device *)dev;
    struct sco_stream_out *out;
    int ret;

    out = (struct sco_stream_out *)calloc(1, sizeof(struct sco_stream_out));
    if (!out)
        return -ENOMEM;

    out->stream.common.get_sample_rate = out_get_sample_rate;
    out->stream.common.set_sample_rate = out_set_sample_rate;
    out->stream.common.get_buffer_size = out_get_buffer_size;
    out->stream.common.get_channels = out_get_channels;
    out->stream.common.get_format = out_get_format;
    out->stream.common.set_format = out_set_format;
    out->stream.common.standby = out_standby;
    out->stream.common.dump = out_dump;
    out->stream.common.set_parameters = out_set_parameters;
    out->stream.common.get_parameters = out_get_parameters;
    out->stream.common.add_audio_effect = out_add_audio_effect;
    out->stream.common.remove_audio_effect = out_remove_audio_effect;
    out->stream.get_latency = out_get_latency;
    out->stream.set_volume = out_set_volume;
    out->stream.write = out_write;
    out->stream.get_render_position = out_get_render_position;
    out->stream.get_next_write_timestamp = out_get_next_write_timestamp;

    *stream_out = &out->stream;
    return 0;
}

static void adev_close_output_stream(struct audio_hw_device *dev,
                                     struct audio_stream_out *stream)
{
    ALOGV("adev_close_output_stream...");
    free(stream);
}

static int adev_set_parameters(struct audio_hw_device *dev, const char *kvpairs)
{
    status_t status = NO_ERROR;
    android::String8 key, value;
    AudioParameter params = AudioParameter(android::String8(kvpairs));

    key = android::String8(PARAM_VOICE_SEARCH_VID);
    if (params.get(key, value) == NO_ERROR) {
        mSearchSourceVid = value;
    }

    key = android::String8(PARAM_VOICE_SEARCH_PID);
    if (params.get(key, value) == NO_ERROR) {
        mSearchSourcePid = value;
    }


    key = android::String8(PARAM_VOICE_SEARCH_SERIAL);
    if (params.get(key, value) == NO_ERROR) {
       mSearchSourceSerial = value;
    }

    return status;
}

static char * adev_get_parameters(const struct audio_hw_device *dev,
                                  const char *keys)
{
    AudioParameter params = AudioParameter(android::String8(keys));
    AudioParameter out_params = AudioParameter();
    android::String8 value, key;

    key = android::String8(PARAM_VOICE_SEARCH_VID);
    if (params.get(key, value) == NO_ERROR) {
        out_params.add(key, android::String8(mSearchSourceVid));
    }

    key = android::String8(PARAM_VOICE_SEARCH_PID);
    if (params.get(key, value) == NO_ERROR) {
        out_params.add(key, android::String8(mSearchSourcePid));
    }

    key = android::String8(PARAM_VOICE_SEARCH_SERIAL);
    if (params.get(key, value) == NO_ERROR) {
        out_params.add(key, android::String8(mSearchSourceSerial));
    }
    return strdup(out_params.toString().string());
}

static int adev_init_check(const struct audio_hw_device *dev)
{
    return 0;
}

static int adev_set_voice_volume(struct audio_hw_device *dev, float volume)
{
    return -ENOSYS;
}

static int adev_set_master_volume(struct audio_hw_device *dev, float volume)
{
    return -ENOSYS;
}

static int adev_get_master_volume(struct audio_hw_device *dev, float *volume)
{
    return -ENOSYS;
}

static int adev_set_master_mute(struct audio_hw_device *dev, bool muted)
{
    return -ENOSYS;
}

static int adev_get_master_mute(struct audio_hw_device *dev, bool *muted)
{
    return -ENOSYS;
}

static int adev_set_mode(struct audio_hw_device *dev, audio_mode_t mode)
{
    return 0;
}

static int adev_set_mic_mute(struct audio_hw_device *dev, bool state)
{
    return -ENOSYS;
}

static int adev_get_mic_mute(const struct audio_hw_device *dev, bool *state)
{
    return -ENOSYS;
}

static size_t adev_get_input_buffer_size(const struct audio_hw_device *dev,
                                         const struct audio_config *config)
{
    return 480;
}

static int adev_open_input_stream(struct audio_hw_device *dev,
                                  audio_io_handle_t handle,
                                  audio_devices_t devices,
                                  struct audio_config *config,
                                  struct audio_stream_in **stream_in,
                                  audio_input_flags_t flags __unused,
                                  const char *address __unused,
                                  audio_source_t source __unused)
{
    ALOGV("adev_open_input_stream...");

    struct sco_audio_device *ladev = (struct sco_audio_device *)dev;
    struct sco_stream_in *in;

    in = (struct sco_stream_in *)calloc(1, sizeof(struct sco_stream_in));
    if (!in)
        return -ENOMEM;

    in->stream.common.get_sample_rate = in_get_sample_rate;
    in->stream.common.set_sample_rate = in_set_sample_rate;
    in->stream.common.get_buffer_size = in_get_buffer_size;
    in->stream.common.get_channels = in_get_channels;
    in->stream.common.get_format = in_get_format;
    in->stream.common.set_format = in_set_format;
    in->stream.common.standby = in_standby;
    in->stream.common.dump = in_dump;
    in->stream.common.set_parameters = in_set_parameters;
    in->stream.common.get_parameters = in_get_parameters;
    in->stream.common.add_audio_effect = in_add_audio_effect;
    in->stream.common.remove_audio_effect = in_remove_audio_effect;
    in->stream.set_gain = in_set_gain;
    in->stream.read = in_read;
    in->stream.get_input_frames_lost = in_get_input_frames_lost;

    *stream_in = &in->stream;

    pthread_mutex_init(&in->lock, NULL);
    in->standby = true;
    in->time_last = GetTickCount();
    in->counter_iteration = 0;
    in->counter_size = 0;
    in->time_max_delta = 0;
    in->time_iteration_begin = GetTickCount();

    in->dump_enabled = 0;
    in->dump_fp = NULL;
    char property[PROPERTY_VALUE_MAX] = {0};
    if (property_get("dump.sco", property, NULL) > 0) {
        if (atoi(property)) {
            in->dump_enabled = 1;
        }
    }
    return 0;
}

static void adev_close_input_stream(struct audio_hw_device *dev,
                                   struct audio_stream_in *stream)
{
    ALOGV("adev_close_input_stream...");
    struct sco_stream_in *in = (struct sco_stream_in *)stream;
    pthread_mutex_lock(&in->lock);
    if (!in->standby) {
        in->standby = true;
        pthread_join(in->tx_id, NULL);
    }
    pthread_mutex_unlock(&in->lock);
    if (bt_socket) {
        close(bt_socket);
        bt_socket = -1;
    }
    if (in->dump_fp) {
       fclose(in->dump_fp);
       in->dump_fp = NULL;
    }
    pthread_mutex_destroy(&in->lock);
    return;
}

static int adev_dump(const audio_hw_device_t *device, int fd)
{
    return 0;
}

static int adev_close(hw_device_t *device)
{
    if (bt_socket) {
        close(bt_socket);
        bt_socket = -1;
    }
    free(device);
    return 0;
}

static int adev_open(const hw_module_t* module, const char* name,
                     hw_device_t** device)
{
    ALOGV("adev_open: %s", name);

    int ret;

    if (strcmp(name, AUDIO_HARDWARE_INTERFACE) != 0)
        return -EINVAL;

    adev = (struct sco_audio_device *) calloc(1, sizeof(struct sco_audio_device));
    if (!adev)
        return -ENOMEM;

    adev->device.common.tag = HARDWARE_DEVICE_TAG;
    adev->device.common.version = AUDIO_DEVICE_API_VERSION_2_0;
    adev->device.common.module = (struct hw_module_t *) module;
    adev->device.common.close = adev_close;

    adev->device.init_check = adev_init_check;
    adev->device.set_voice_volume = adev_set_voice_volume;
    adev->device.set_master_volume = adev_set_master_volume;
    adev->device.get_master_volume = adev_get_master_volume;
    adev->device.set_master_mute = adev_set_master_mute;
    adev->device.get_master_mute = adev_get_master_mute;
    adev->device.set_mode = adev_set_mode;
    adev->device.set_mic_mute = adev_set_mic_mute;
    adev->device.get_mic_mute = adev_get_mic_mute;
    adev->device.set_parameters = adev_set_parameters;
    adev->device.get_parameters = adev_get_parameters;
    adev->device.get_input_buffer_size = adev_get_input_buffer_size;
    adev->device.open_output_stream = adev_open_output_stream;
    adev->device.close_output_stream = adev_close_output_stream;
    adev->device.open_input_stream = adev_open_input_stream;
    adev->device.close_input_stream = adev_close_input_stream;
    adev->device.dump = adev_dump;

    *device = &adev->device.common;

    return 0;
}

static struct hw_module_methods_t hal_module_methods = {
    .open = adev_open,
};

struct audio_module HAL_MODULE_INFO_SYM = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .module_api_version = AUDIO_MODULE_API_VERSION_0_1,
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = AUDIO_HARDWARE_MODULE_ID,
        .name = "SCO Audio HAL for MT7668",
        .author = "chiqin@amazon.com",
        .methods = &hal_module_methods,
    },
};
