/*
 * Copyright (C) 2014 FUJITSU LIMITED
 * Author Wen Congyang <wency@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

#include <string.h>
#include <sys/un.h>

#define     BLKTAP2_REQUEST     "flush"
#define     BLKTAP2_RESPONSE    "done"
#define     BLKTAP_CTRL_DIR     "/var/run/tap"

typedef struct libxl__remus_blktap2_disk {
    char *name;
    char *ctl_fifo_path;
    char *msg_fifo_path;
    int ctl_fd;
    int msg_fd;
    libxl__ev_fd ev;
    libxl__remus_device *dev;
}libxl__remus_blktap2_disk;

int init_subkind_blktap_disk(libxl__remus_devices_state *rds)
{
    return 0;
}

void cleanup_subkind_blktap_disk(libxl__remus_devices_state *rds)
{
    return;
}
/* ========== setup() and teardown() ========== */
static void blktap2_remus_setup(libxl__egc *egc, libxl__remus_device *dev)
{
    const libxl_device_disk *disk = dev->backend_dev;
    libxl__remus_blktap2_disk *blktap2_disk;
    int rc;
    int i, l;

    STATE_AO_GC(dev->rds->ao);

    if (disk->backend != LIBXL_DISK_BACKEND_TAP ||
        !disk->filter ||
        strcmp(disk->filter, "remus")) {
        rc = ERROR_REMUS_DEVOPS_DOES_NOT_MATCH;
        goto out;
    }

    dev->matched = 1;
    GCNEW(blktap2_disk);
    dev->concrete_data = blktap2_disk;
    blktap2_disk->ctl_fd = -1;
    blktap2_disk->msg_fd = -1;
    blktap2_disk->dev = dev;

    blktap2_disk->name = libxl__strdup(gc, disk->filter_params);
    blktap2_disk->ctl_fifo_path = GCSPRINTF("%s/remus_%s",
                                            BLKTAP_CTRL_DIR,
                                            blktap2_disk->name);
    /* scrub fifo pathname */
    l = strlen(blktap2_disk->ctl_fifo_path);
    for (i = strlen(BLKTAP_CTRL_DIR) + 1; i < l; i++) {
        if (strchr(":/", blktap2_disk->ctl_fifo_path[i]))
            blktap2_disk->ctl_fifo_path[i] = '_';
    }
    blktap2_disk->msg_fifo_path = GCSPRINTF("%s.msg",
                                            blktap2_disk->ctl_fifo_path);

    blktap2_disk->ctl_fd = open(blktap2_disk->ctl_fifo_path, O_WRONLY);
    blktap2_disk->msg_fd = open(blktap2_disk->msg_fifo_path, O_RDONLY);
    if (blktap2_disk->ctl_fd < 0 || blktap2_disk->msg_fd < 0) {
        rc = ERROR_FAIL;
        goto out;
    }

    libxl__ev_fd_init(&blktap2_disk->ev);

    rc = 0;

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

static void blktap2_remus_teardown(libxl__egc *egc,
                                   libxl__remus_device *dev)
{
    libxl__remus_blktap2_disk *blktap2_disk = dev->concrete_data;

    if (blktap2_disk->ctl_fd > 0) {
        close(blktap2_disk->ctl_fd);
        blktap2_disk->ctl_fd = -1;
    }

    if (blktap2_disk->msg_fd > 0) {
        close(blktap2_disk->msg_fd);
        blktap2_disk->msg_fd = -1;
    }

    dev->aodev.rc = 0;
    dev->aodev.callback(egc, &dev->aodev);
}

/* ========== checkpointing APIs ========== */
/*
 * When a new checkpoint is triggered, we do the following thing:
 *  1. send BLKTAP2_REQUEST to tapdisk2
 *  2. tapdisk2 send "creq"
 *  3. secondary vm's tapdisk2 reply "done"
 *  4. tapdisk2 writes BLKTAP2_RESPONSE to the socket
 *  5. read BLKTAP2_RESPONSE from the socket
 * Step1 and 5 are implemented here.
 */
static void blktap2_control_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                     int fd, short events, short revents);

static void blktap2_remus_postsuspend(libxl__egc *egc,
                                      libxl__remus_device *dev)
{
    int ret;
    libxl__remus_blktap2_disk *blktap2_disk = dev->concrete_data;
    int rc = 0;

    /* fifo fd, and not block */
    ret = write(blktap2_disk->ctl_fd, BLKTAP2_REQUEST, strlen(BLKTAP2_REQUEST));
    if (ret < strlen(BLKTAP2_REQUEST))
        rc = ERROR_FAIL;

    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

static void blktap2_remus_commit(libxl__egc *egc,
                                 libxl__remus_device *dev)
{
    libxl__remus_blktap2_disk *blktap2_disk = dev->concrete_data;
    int rc;

    /* Convenience aliases */
    const int fd = blktap2_disk->msg_fd;
    libxl__ev_fd *const ev = &blktap2_disk->ev;

    STATE_AO_GC(dev->rds->ao);

    rc = libxl__ev_fd_register(gc, ev, blktap2_control_readable, fd, POLLIN);
    if (rc) {
        dev->aodev.rc = rc;
        dev->aodev.callback(egc, &dev->aodev);
    }
}

static void blktap2_control_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                     int fd, short events, short revents)
{
    libxl__remus_blktap2_disk *blktap2_disk =
                CONTAINER_OF(ev, *blktap2_disk, ev);
    int rc = 0, ret;
    char response[5];

    /* Convenience aliases */
    libxl__remus_device *const dev = blktap2_disk->dev;

    EGC_GC;

    libxl__ev_fd_deregister(gc, ev);

    if (revents & ~POLLIN) {
        LOG(ERROR, "unexpected poll event 0x%x (should be POLLIN)", revents);
        rc = ERROR_FAIL;
        goto out;
    }

    ret = read(fd, response, sizeof(response) - 1);
    if (ret < sizeof(response) - 1) {
        rc = ERROR_FAIL;
        goto out;
    }

    response[4] = '\0';
    if (strcmp(response, BLKTAP2_RESPONSE))
        rc = ERROR_FAIL;

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}


const libxl__remus_device_instance_ops remus_device_blktap2_disk = {
    .kind = LIBXL__DEVICE_KIND_VBD,
    .setup = blktap2_remus_setup,
    .teardown = blktap2_remus_teardown,
    .postsuspend = blktap2_remus_postsuspend,
    .commit = blktap2_remus_commit,
};
