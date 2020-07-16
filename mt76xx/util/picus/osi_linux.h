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

#ifndef __OSI_LINUX_H__
#define __OSI_LINUX_H__
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

typedef struct sigaction SIGACTION;
typedef struct flock FLOCK;
typedef struct dirent DIRENT;
typedef struct timeval TIMEVAL;
typedef struct timezone TIMEZONE;
typedef struct stat STAT;

typedef fd_set osi_fd_set;
typedef pthread_mutex_t PTHREAD_MUTEX_T;
typedef pthread_t PTHREAD_T;
typedef size_t SIZE_T;
typedef ssize_t SSIZE_T;
typedef time_t TIME_T;
typedef pthread_mutex_t OSI_PTHREAD_MUTEX_T;
typedef pthread_attr_t PTHREAD_ATTR_T;
typedef pthread_mutexattr_t PTHREAD_MUTEXATTR_T;


#define OSI_FILE FILE
#define OSI_RDWR O_RDWR
#define OSI_NOCTTY O_NOCTTY
#define OSI_NONBLOCK O_NONBLOCK
#define OSI_O_WRONLY O_WRONLY
#define OSI_O_NONBLOCK O_NONBLOCK
#define OSI_F_SETLK F_SETLK
#define OSI_F_UNLCK F_UNLCK
#define OSI_SEEK_SET SEEK_SET
#define OSI_F_SETLKW F_SETLKW
void DBGPRINT(int level, const char *format, ...);
void init_sigaction(SIGACTION *sigact, void *handler);
void init_flock(FLOCK *flk);
int osi_mkfifo(const char *pathname, mode_t mode);
int osi_system(const char *cmd);
int osi_open(const char *path, int oflag);
int osi_close(int fd);
int osi_fclose(FILE *stream);
int OSI_STAT(const char *path);
int osi_usleep(int micro_second);
DIR *osi_opendir(const char *name);
struct dirent *osi_readdir(DIR *dirp);
char *osi_get_dirent_name(DIRENT *dirent);
int osi_closedir(DIR *dirp);
int osi_remove(const char *pathname);
TIME_T osi_time(TIME_T *t);
SIZE_T osi_strftime(char *s, SIZE_T max, const char *format,
                       const struct tm *tm);
struct tm *osi_localtime(const TIME_T *timep);
FILE *osi_fopen(const char *pathname, const char *mode);
int osi_gettimeofday(TIMEVAL *tv, TIMEZONE *tz);
int osi_select(int nfds, osi_fd_set *readfds, osi_fd_set *writefds,
           osi_fd_set *exceptfds, struct timeval *timeout);
int  osi_FD_ISSET(int fd, osi_fd_set *set);
void  osi_FD_SET(int fd, osi_fd_set *set);
SSIZE_T osi_read(int fd, void *buf, SIZE_T count);
SSIZE_T osi_write(int fd, const void *buf, SIZE_T count);
SIZE_T osi_fwrite(const void *ptr, SIZE_T size, SIZE_T nitems,
           FILE *stream);
int osi_fcntl(int fd, int cmd, FLOCK *lock);
int osi_fflush(FILE *stream);
void fillheader(unsigned char *header, int headerlen,
        unsigned short int dump_file_seq_num);
void set_timeval(TIMEVAL *tv, int sec, int usec);
void unlock_device_node(int fd, FLOCK *fl, int type, int whence);
int osi_getopt(int nargc, char * const *nargv, const char *ostr);
void osi_pthread_mutex_lock(OSI_PTHREAD_MUTEX_T *xSemaphore);
void osi_pthread_mutex_unlock(OSI_PTHREAD_MUTEX_T *xSemaphore);
int osi_pthread_create(PTHREAD_T *thread, const PTHREAD_ATTR_T *attr,
                          void *(*start_routine) (void *), void *arg);
int osi_pthread_mutex_init(PTHREAD_MUTEX_T *mutex,
           const PTHREAD_MUTEXATTR_T *attr);
int osi_pthread_mutex_destroy(PTHREAD_MUTEX_T *mutex);
int osi_usleep(int micro_second);
int osi_sleep_ms(int ms);
uint16_t osi_htobe16(uint16_t host_16bits);
uint32_t osi_htobe32(uint32_t host_32bits);
uint64_t osi_htobe64(uint64_t host_64bits);
#endif /*__OSI_LINUX_H__*/
