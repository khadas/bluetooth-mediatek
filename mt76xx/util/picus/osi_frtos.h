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

#ifndef __OSI_FRTOS_H__
#define __OSI_FRTOS_H__

#include "FreeRTOS.h"
#include "semphr.h"
#include "task_def.h"
#include "task.h"

typedef int SIGACTION;
typedef int FLOCK;
typedef int DIRENT;
typedef int DIR;
typedef int TIMEVAL;
typedef int TIMEZONE;
typedef int STAT;
typedef int MODE_T;
typedef unsigned int SIZE_T;
typedef int SSIZE_T;
typedef int TIME_T;
typedef int OSI_FILE;
typedef int osi_fd_set;
typedef int osi_uint64_t;
typedef int TM;
typedef SemaphoreHandle_t  PTHREAD_MUTEX_T;
typedef int PTHREAD_T;
typedef int PTHREAD_ATTR_T;
typedef int PTHREAD_MUTEXATTR_T;
#ifndef NULL
#define NULL 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 100
#endif


#define OSI_RDWR  0
#define OSI_NOCTTY 0
#define OSI_NONBLOCK 0
#define OSI_O_WRONLY 0
#define OSI_O_NONBLOCK 0
#define OSI_F_SETLK 0
#define OSI_F_UNLCK 0
#define OSI_SEEK_SET 0
#define OSI_F_SETLKW 0
#define NAME_MAX 100

extern int g_debuglevel;

void init_sigaction(SIGACTION *sigact, void *handler);
void init_flock(FLOCK *flk);
int osi_mkfifo(const char *pathname, MODE_T mode);
int osi_system(const char *cmd);
int osi_open(const char *path, int oflag);
int osi_close(int fd);
int osi_fclose(int *stream);
int OSI_STAT(const char *path);
int osi_usleep(int micro_second);
DIR *osi_opendir(const char *name);
DIRENT *osi_readdir(DIR *dirp);
char *osi_get_dirent_name(DIRENT *dirent);
int osi_closedir(DIR *dirp);
int osi_remove(const char *pathname);
TIME_T osi_time(TIME_T *t);
SIZE_T osi_strftime(char *s, SIZE_T max, const char *format,
                       const TM *tm);
TM *osi_localtime(const TIME_T *timep);
OSI_FILE *osi_fopen(const char *pathname, const char *mode);
int osi_select(int nfds, osi_fd_set *readfds, osi_fd_set *writefds,
           osi_fd_set *exceptfds, TIMEVAL *timeout);
int  osi_FD_ISSET(int fd, osi_fd_set *set);
void  osi_FD_SET(int fd, osi_fd_set *set);
SSIZE_T osi_read(int fd, void *buf, SIZE_T count);
SSIZE_T osi_write(int fd, const void *buf, SIZE_T count);
SSIZE_T osi_fwrite(unsigned char *ptr, SIZE_T size, SIZE_T nitems,
           OSI_FILE *stream);
int osi_fcntl(int fd, int cmd, FLOCK *lock);
int osi_fflush(OSI_FILE *stream);
void fillheader(unsigned char *header, int headerlen,
        unsigned short int dump_file_seq_num);
void set_timeval(TIMEVAL *tv, int sec, int usec);
void unlock_device_node(int fd, FLOCK *fl, int type, int whence);
int osi_getopt(int nargc, char * const *nargv, const char *ostr);
void osi_pthread_mutex_lock(PTHREAD_MUTEX_T *xSemaphore);
void osi_pthread_mutex_unlock(PTHREAD_MUTEX_T *xSemaphore);
TaskHandle_t osi_pthread_create(PTHREAD_T *thread, const PTHREAD_ATTR_T *attr,
                          void *start_routine, void *arg);
int osi_pthread_mutex_init(PTHREAD_MUTEX_T *mutex,
           const PTHREAD_MUTEXATTR_T *attr);
int osi_pthread_mutex_destroy(PTHREAD_MUTEX_T *mutex);
int osi_sleep_ms(int ms);
unsigned short int osi_htobe16(unsigned short int input_val);
unsigned int osi_htobe32(unsigned int input_val);
uint64_t osi_htobe64(uint64_t input_val);
#endif /* __OSI_FRTOS_H__ */
