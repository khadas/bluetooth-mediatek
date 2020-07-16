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

#include "osi_frtos.h"
#include "common.h"
#include "btmtk_common.h"
#include "task_def.h"
#include "task.h"

char *ppicus_optarg;
int *ppicus_optind;
//int *ppicus_optind = &picus_optind;

void init_sigaction(SIGACTION *sigact, void *handler)
{
    return;
}

void init_flock(FLOCK *flk)
{
    return;
}

int osi_mkfifo(const char *pathname, MODE_T mode)
{
    return 0;
}

/*convert two char to value*/
unsigned char convert_string_to_value(char *array, int len)
{
    unsigned char value;
    if (array == NULL)
        return 0;

    if (len == 2) {
        if (array[0] >= '0' && array[0] <= '9')
            value = (array[0] - 48) *16;
        else if (array[0] >= 'a' && array[0] <= 'f')
            value = (array[0] - 87) *16;
        else if (array[0] >= 'A' && array[0] <= 'F')
            value = (array[0] - 55) *16;
        else
            return 0;

        if (array[1] >= '0' && array[1] <= '9')
            value += (array[1] - 48);
        else if (array[1] >= 'a' && array[1] <= 'f')
            value += (array[1] - 87);
        else if (array[1] >= 'A' && array[1] <= 'F')
            value += (array[1] - 55);
        else
            return 0;

    } else
        return 0;

    return value;
}

/* Input shodld be echo xx xx xx xx ....  > ....
 *
 *
 */

#define ECHO_STR "echo "
#define ECHO_BPERF "bperf="

int osi_system(const char *cmd)
{/*osi_system("echo 01 be fc 01 00 > "FWLOG_DEV); */
    char *begin, *end, *current;
    char value_str[3];
    int i = 0;
    unsigned char parsing_len;
    unsigned char *cmdbuf;
    unsigned char cmd_len;
    char *bperf;
    int ret = 0;
    int enable = 0;
    char enable_str[2];

    DBGPRINT(SHOW, "%s %s", __FUNCTION__, cmd);
    if (cmd == NULL)
        return 0;

    begin = strstr(cmd, ECHO_STR);
    end = strstr(cmd, ">");

    if (begin == NULL || end == NULL)
        return 0;

    bperf = strstr(cmd, ECHO_BPERF);
    if (bperf) {
        enable_str[0] = bperf[strlen(ECHO_BPERF)];
        enable_str[1] = 0;
        enable = atoi(enable_str);
        btmtk_com_set_bluetooth_kpi(enable);
    } else {/*send cmd user assigned*/
        memset(value_str, 0, sizeof(value_str));
        current = begin;
        current += strlen(ECHO_STR);

        parsing_len = end - current;
        cmdbuf = malloc(parsing_len / 2);
        cmd_len = (parsing_len / 3);
        for (i = 0; i < cmd_len;i++) {
            value_str[0] = *current++;
            value_str[1] = *current++;
            current++;
            cmdbuf[i] = convert_string_to_value(value_str, 2);
            if (ret)
                printf("%s convert fail\n", __func__);
        }

        btmtk_com_tx(cmdbuf, cmd_len);

        free(cmdbuf);
    }


    return 0;
}

unsigned char g_need_print_first_event = 0;
TaskHandle_t g_background_task_handle = 0;
int picus_main(int argc, char *argv[]);
extern TaskHandle_t create_picus_srv(void);
TaskHandle_t g_handle_notify_app = 0;/*notify app, picus service is ready*/

int priv_argc = 0;

void picus_main_background(void * pvParameters)
{
    picus_main(priv_argc, pvParameters);
    printf("picus_main_background picus_main done\n");
    g_background_task_handle = NULL;
    vTaskDelete(NULL);
}

/* return value 1: create success or already created for current task
 * return value 0: created task run to here
 */
bool open_background_task(TaskHandle_t notifyApphandle, int argc, char *argv[])
{
    BaseType_t xReturned = 0;
    g_handle_notify_app = notifyApphandle;
    if (!g_background_task_handle) {
        priv_argc = argc;
        xReturned = xTaskCreate(
            picus_main_background,
            "Picusbackroundmaintask",
            2000,
            (void*)argv,
            tskIDLE_PRIORITY,
            &g_background_task_handle);

        if (xReturned == pdPASS) {
            btmtk_com_set_rx_picus_notify_task_handle(g_background_task_handle);
            DBGPRINT(SHOW, "%s Picus backround main task create success", __func__);
            return 1;
        } else {
            DBGPRINT(SHOW, "%s Picus backround main task create fail", __func__);
            return 0;
        }
    }

    if (xTaskGetCurrentTaskHandle() == g_background_task_handle)
        return 0;/*this task is create by picus*/
    else
        return 1;

    return 1;
}
static bool g_picus_first_run = 1;
OSI_FILE osi_open(const char *path, int oflag)
{
    BaseType_t xReturned = 0;
    DBGPRINT(ERROR, "%s path = %s", __FUNCTION__, path);
    if (strncmp(CUST_BT_FWLOG_PORT, path, strlen(CUST_BT_FWLOG_PORT) - 1) == 0) {
        if (g_picus_first_run) {
            g_picus_first_run = 0;
            return FD_DRIVER_DBGNODE;/*task create success and main goto done*/
        }

        return -1;/*task create before and main goto done*/
    } else if (strncmp(HCI_FIFO_PATH, path, strlen(HCI_FIFO_PATH) - 1) == 0) {
        g_need_print_first_event = 1;
        DBGPRINT(ERROR, "%s return FD_HCIFIFO %d", __FUNCTION__, FD_HCIFIFO);
        return FD_HCIFIFO;
    }

    DBGPRINT(ERROR, "Open %s, return fail 0", path);
    return -1;
}
char g_write_data[32]  = {0};
SSIZE_T osi_read(int fd, void *buf, SIZE_T count)
{
    SIZE_T ret = 0;
    int copy_size = count;

    //DBGPRINT(SHOW, "%s fd = %d, count %d", __FUNCTION__, fd, count);
    if (fd == FD_HCIFIFO) {
        if (strlen(g_write_data) > 0) {
            if (strlen(g_write_data) > strlen(g_write_data))
                copy_size = strlen(g_write_data);

            memcpy(buf, g_write_data, copy_size);
            memset(g_write_data, 0, sizeof(g_write_data));
            return copy_size;
        }
        return 0;
    } else if (fd == FD_DRIVER_DBGNODE)/*read data from driver*/
        ret = btmtk_com_rx_fwlog(buf, count);

    return ret;
}

SSIZE_T osi_write(int fd, const void *buf, SIZE_T count)
{
    int copy_size = count;

    DBGPRINT(SHOW, "%s fd = %d", __FUNCTION__, fd);
    if (fd == FD_HCIFIFO) {
        if (strlen(g_write_data) > strlen(g_write_data))
            copy_size = strlen(g_write_data);

        memcpy(g_write_data, buf, copy_size);
    }

    return 0;
}

int osi_close(int fd)
{
    return 0;
}

int OSI_STAT(const char *path)
{
    return 0;
}

int osi_sleep_ms(int ms)
{
    const TickType_t xDelay = ms / portTICK_PERIOD_MS;
    vTaskDelay(xDelay);
    return 0;
}

int osi_usleep(int micro_second)
{
    osi_sleep_ms(micro_second / 1000);
    return 0;
}

DIR *osi_opendir(const char *name)
{
    return NULL;
}

DIRENT *osi_readdir(DIR *dirp)
{
    return NULL;
}

char *osi_get_dirent_name(DIRENT *dirent)
{
    return NULL;
}

int osi_closedir(DIR *dirp)
{
    return 0;
}

int osi_remove(const char *pathname)
{
    return 0;
}

TIME_T osi_time(TIME_T *t)
{
    return 0;
}

SIZE_T osi_strftime(char *s, SIZE_T max, const char *format, const TM *tm)
{
    return 0;
}

TM *osi_localtime(const TIME_T *timep)
{
    return NULL;
}

OSI_FILE g_picusfile = FD_PICUS_FILE;
OSI_FILE g_dumpfile = FD_FWDUMP_FILE;/*fw dump*/
OSI_FILE *osi_fopen(const char *pathname, const char *mode)
{
    if (strstr(pathname,DUMP_PICUS_NAME_PREFIX))
        return &g_picusfile;/*open dump file*/

    if (strstr(pathname,FW_DUMP_PICUS_NAME))
        return &g_dumpfile;/*open dump file*/

    return NULL;
}


extern void bt_hci_log_nxp(uint32_t type, unsigned char *data, uint32_t length);
SSIZE_T osi_fwrite(unsigned char *ptr, SIZE_T size, SIZE_T nitems,
           OSI_FILE *stream)
{   /* pass to frontline */
    if (*stream == FD_PICUS_FILE)
        bt_hci_log_nxp(10/*0x4*/, (unsigned char *)ptr, nitems);

    return 0;
}

int osi_select(int nfds, osi_fd_set *readfds, osi_fd_set *writefds,
           osi_fd_set *exceptfds, TIMEVAL *timeout)
{/*wait data from driver*/
    if (g_handle_notify_app) {/*wake up app for service is ready, only wake up once*/
        xTaskNotifyGive(g_handle_notify_app);
        g_handle_notify_app = 0;
    }

    ulTaskNotifyTake(pdFALSE , portMAX_DELAY);
    //DBGPRINT(SHOW, "%s end", __FUNCTION__);
    return FD_DRIVER_DBGNODE;
}

int  osi_FD_ISSET(int fd, osi_fd_set *set)
{
    return 1;
}

void  osi_FD_SET(int fd, osi_fd_set *set)
{
    return;
}

int osi_fclose(int *stream)
{
    return 0;
}

int osi_fcntl(int fd, int cmd, FLOCK *lock)
{
    return 1;
}

int osi_fflush(OSI_FILE *stream)
{
    return 0;
}

unsigned short int osi_htobe16(unsigned short int input_val)
{
    unsigned short int temp = 0;
    temp = (input_val & 0x00FF) << 8;
    temp |= ((input_val & 0xFF00) >> 8) & 0x00FF;
    return temp;
}

unsigned int osi_htobe32(unsigned int input_val)
{
    int temp = 0;
    temp = (input_val & 0x000000FF) << 24;
    temp |= (input_val & 0x0000FF00) << 8;
    temp |= ((input_val & 0x00FF0000) >> 8) & 0x0000FF00;
    temp |= ((input_val & 0xFF000000) >> 24) & 0x000000FF;
    return temp;
}

uint64_t osi_htobe64(uint64_t input_val)
{
    int temp = 0;
    temp = (input_val & 0x00000000000000FF) << 56;
    temp = (input_val & 0x000000000000FF00) << 40;
    temp = (input_val & 0x0000000000FF0000) << 24;
    temp =   (input_val & 0x00000000FF000000) << 8;
    temp |= ((input_val & 0x000000FF00000000) >> 8) & 0x00000000FF000000;
    temp |= ((input_val & 0x0000FF0000000000) >> 24) & 0x0000000000FF0000;
    temp |= ((input_val & 0x00FF000000000000) >> 40) & 0x000000000000FF00;
    temp |= ((input_val & 0xFF00000000000000) >> 56) & 0x00000000000000FF;
    return temp;
}

void set_timeval(TIMEVAL *tv, int sec, int usec)
{
    return;
}

void unlock_device_node(int fd, FLOCK *fl, int type, int whence)
{
    return;
}

unsigned char parsing_total_param = 0;

void osi_getopt_clean()
{
    parsing_total_param = 0;
}

int osi_getopt(int nargc, char * const *nargv, const char *ostr)
{
    int i = 0, j = 0;
    int ostr_len = 0;
    char target_str[3];
    char find_cmd = 0;
    char *find_arg = NULL;
    static int f_picus_optind;
    static char f_picus_optarg[300];
    char *temp;

    memset(f_picus_optarg, 0, sizeof(f_picus_optarg));
    f_picus_optind = -1;

    if (nargv == NULL) {
        DBGPRINT(SHOW, "%s nargv is NULL\n", __FUNCTION__);
        return -1;
    }

    ppicus_optarg = f_picus_optarg;
    ppicus_optind = &f_picus_optind;

    target_str[0] = '-';
    ostr_len = strlen(ostr);

    /* find -x first */
    for (i = parsing_total_param; i < nargc; i++) {
        find_arg = strstr(nargv[i], target_str);
        if (find_arg) {
            target_str[1] = find_arg[1];
            DBGPRINT(TRACE, "%s nargv[%d] find %s\n", __FUNCTION__, i, target_str);
            /* find if -x is in ostr list */
            temp = strstr(ostr, &target_str[1]);
            if (temp) {/*find parameter setting value and finish this run*/
                if (i + 1 < nargc) {
                    strcpy(f_picus_optarg, nargv[i + 1]);
                    f_picus_optind = i + 1;
                }
                parsing_total_param = i + 1;
                DBGPRINT(TRACE, "%s return %c\n", __FUNCTION__, target_str[1]);
                return target_str[1];
            }

        }
    }

    DBGPRINT(TRACE, "%s return -1\n", __FUNCTION__);
    return -1;
}

void osi_pthread_mutex_lock(PTHREAD_MUTEX_T *xSemaphore)
{
    if (xSemaphore == NULL)
        *xSemaphore = xSemaphoreCreateMutex();

    xSemaphoreTake(*xSemaphore, portMAX_DELAY);
}

void osi_pthread_mutex_unlock(PTHREAD_MUTEX_T *xSemaphore)
{
    if (*xSemaphore == NULL)
        return;

    xSemaphoreGive(*xSemaphore);
}

TaskHandle_t osi_pthread_create(PTHREAD_T *thread, const PTHREAD_ATTR_T *attr,
                          void *start_routine, void *arg)
{
    BaseType_t xReturned;
    TaskHandle_t Handle;
    /* Create the task, storing the handle. */
    xReturned = xTaskCreate(
        start_routine,       /* Function that implements the task. */
        "Picus task",        /* Text name for the task. */
        400,                 /* Stack size in words, not bytes. */
        ( void * ) 1,        /* Parameter passed into the task. */
        TASK_PRIORITY_SOFT_REALTIME,/* tskIDLE_PRIORITY Priority at which the task is created. */
        &Handle );           /* Used to pass out the created task's handle. */

    if ( xReturned == pdPASS ) {
        /* The task was created.  Use the task's handle to delete the task. */
        DBGPRINT(SHOW, "task create success\n", __func__);
    } else
        DBGPRINT(SHOW, "task create fail\n", __func__);
    return Handle;
}

int osi_pthread_mutex_init(PTHREAD_MUTEX_T *mutex,
           const PTHREAD_MUTEXATTR_T *attr)
{
    if (mutex != NULL) {
        DBGPRINT(TRACE, "%s call xSemaphoreCreateMutex\n", __func__);
        *mutex = xSemaphoreCreateMutex();
    } else
        DBGPRINT(TRACE, "%s not call xSemaphoreCreateMutex\n", __func__);
    return 0;
}

int osi_pthread_mutex_destroy(PTHREAD_MUTEX_T *mutex)
{
    return 0;
}
