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

#include "osi_linux.h"
#include "common.h"
#include "endian.h"

char *picus_optarg;
int picus_optind;

void init_sigaction(SIGACTION *sigact, void *handler)
{
    sigact->sa_handler = handler;
    sigact->sa_flags = 0;
    sigemptyset(&sigact->sa_mask);
    sigaction(SIGINT, sigact, NULL);
    sigaction(SIGTERM, sigact, NULL);
    sigaction(SIGQUIT, sigact, NULL);
    sigaction(SIGKILL, sigact, NULL);
    sigaction(SIGHUP, sigact, NULL);
}

void init_flock(FLOCK *flk)
{
    flk->l_type = F_WRLCK;
    flk->l_whence = SEEK_SET;
    flk->l_pid = getpid();
    flk->l_start = 0;
    flk->l_len = 0;
}

int osi_mkfifo(const char *pathname, mode_t mode)
{
    int ret = 0;

    if ((ret = mkfifo(pathname, mode)) < 0)
        DBGPRINT(ERROR, "create fifo failed(%d)", errno);

    if (errno ==EEXIST)
        DBGPRINT(WARN, "fifo already exist");

    return ret;
}

int osi_system(const char *cmd)
{
    FILE *fp;
    int ret;

    if (cmd == NULL) {
        DBGPRINT(ERROR, "%s: cmd is NULL", __func__);
        return -1;
    }

    fp = popen(cmd, "r");
    if (fp == NULL) {
        DBGPRINT(ERROR, "%s: (%s) failed", __func__, cmd);
        return -1;
    }

    DBGPRINT(ERROR, "Command: %s", cmd);

    ret = pclose(fp);

    if (ret != 0)
        DBGPRINT(ERROR, "%s: pclose ret = %d", __func__, ret);

    return ret;
}

int osi_open(const char *path, int oflag)
{
    return open(path, oflag);
}

int osi_close(int fd)
{
    return close(fd);
}

int OSI_STAT(const char *path)
{
    struct stat sb;

    if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode))
        return 1;
    else
        return 0;
}

int osi_usleep(int micro_second)
{
    return usleep(micro_second);
}

int osi_sleep_ms(int ms)
{
    sleep(ms);
    return 0;
}

DIR *osi_opendir(const char *name)
{
    return opendir(name);
}

struct dirent *osi_readdir(DIR *dirp)
{
    return readdir(dirp);
}

char *osi_get_dirent_name(DIRENT *dirent)
{
    return dirent->d_name;
}

int osi_closedir(DIR *dirp)
{
    return closedir(dirp);
}

int osi_remove(const char *pathname)
{
    return remove(pathname);
}

TIME_T osi_time(TIME_T *t)
{
    return time(t);
}

SIZE_T osi_strftime(char *s, SIZE_T max, const char *format,
                       const struct tm *tm)
{
    return strftime(s, max, format, tm);
}

struct tm *osi_localtime(const TIME_T *timep)
{
    return localtime(timep);
}

FILE *osi_fopen(const char *pathname, const char *mode)
{
    return fopen(pathname, mode);
}

int osi_gettimeofday(TIMEVAL *tv, TIMEZONE *tz)
{
    return gettimeofday(tv, tz);
}

int osi_select(int nfds, osi_fd_set *readfds, osi_fd_set *writefds,
           osi_fd_set *exceptfds, struct timeval *timeout)
{
    return select(nfds, readfds, writefds,
           exceptfds, timeout);
}

int  osi_FD_ISSET(int fd, osi_fd_set *set)
{
    return FD_ISSET(fd, set);
}

void  osi_FD_SET(int fd, osi_fd_set *set)
{
    return FD_SET(fd, set);
}

SSIZE_T osi_read(int fd, void *buf, SIZE_T count)
{
    return read(fd, buf, count);
}

SSIZE_T osi_write(int fd, const void *buf, SIZE_T count)
{
    return write(fd, buf, count);
}

SIZE_T osi_fwrite(const void *ptr, SIZE_T size, SIZE_T nitems,
           FILE *stream)
{
    return fwrite(ptr, size, nitems, stream);
}

int osi_fclose(FILE *stream)
{
    return fclose(stream);
}

int osi_fcntl(int fd, int cmd, FLOCK *lock)
{
    return fcntl(fd, cmd, lock);
}

int osi_fflush(FILE *stream)
{
    return fflush(stream);
}

void set_timeval(TIMEVAL *tv, int sec, int usec)
{
    tv->tv_sec = sec;
    tv->tv_usec = usec;
}

void unlock_device_node(int fd, FLOCK *fl, int type, int whence)
{
    fl->l_type = OSI_F_UNLCK;
    fl->l_whence = OSI_SEEK_SET;
    if (osi_fcntl(fd, OSI_F_SETLKW, fl) < 0)
        DBGPRINT(ERROR, "%s: fcntl failed(%d)", __func__, errno);
}
extern char *ppicus_optarg;
extern int *ppicus_optind;
int osi_getopt(int nargc, char * const *nargv, const char *ostr)
{
    int ret = 0;

    if (nargv == NULL) {
        DBGPRINT(SHOW, "%s nargv is NULL\n", __FUNCTION__);
        return -1;
    }

    ret = getopt(nargc, nargv, ostr);
    ppicus_optarg = optarg;
    ppicus_optind = &optind;
    return ret;
}

void osi_pthread_mutex_lock(OSI_PTHREAD_MUTEX_T *xSemaphore)
{
    pthread_mutex_lock(xSemaphore);
    return;
}

void osi_pthread_mutex_unlock(OSI_PTHREAD_MUTEX_T *xSemaphore)
{
    pthread_mutex_unlock(xSemaphore);
    return;
}

int osi_pthread_create(PTHREAD_T *thread, const PTHREAD_ATTR_T *attr,
                          void *(*start_routine) (void *), void *arg)
{
    return pthread_create(thread, attr,start_routine, arg);

}

int osi_pthread_mutex_init(PTHREAD_MUTEX_T *mutex,
           const PTHREAD_MUTEXATTR_T *attr)
{
    return pthread_mutex_init(mutex, attr);
}

int osi_pthread_mutex_destroy(PTHREAD_MUTEX_T *mutex)
{
    return pthread_mutex_destroy(mutex);
}

uint16_t osi_htobe16(uint16_t host_16bits)
{
    return htobe16(host_16bits);
}

uint32_t osi_htobe32(uint32_t host_32bits)
{
    return htobe32(host_32bits);
}

uint64_t osi_htobe64(uint64_t host_64bits)
{
    return htobe64(host_64bits);
}
