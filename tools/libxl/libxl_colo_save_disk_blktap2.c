/*
 * Copyright (C) 2014 FUJITSU LIMITED
 * Author: Wen Congyang <wency@cn.fujitsu.com>
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

typedef struct libxl__colo_blktap2_disk {
    char *name;
    char *ctl_socket_path;
    int fd;
    libxl__ev_fd ev;
    libxl__checkpoint_device *dev;
}libxl__colo_blktap2_disk;

/* ========== init() and cleanup() ========== */
int init_subkind_blktap2_disk(libxl__checkpoint_devices_state *cds)
{
    return 0;
}

void cleanup_subkind_blktap2_disk(libxl__checkpoint_devices_state *cds)
{
}

/* ========== setup() and teardown() ========== */
static int blktap2_control_connect(libxl__gc *gc,
                                   libxl__colo_blktap2_disk *blktap2_disk)
{
    struct sockaddr_un saddr;
    int fd, err;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG(ERROR, "cannot creating socket fd");
        return ERROR_FAIL;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    strcpy(saddr.sun_path, blktap2_disk->ctl_socket_path);

    err = connect(fd, (const struct sockaddr *)&saddr, sizeof(saddr));
    if (err) {
        LOG(ERROR, "cannot connecte to %s", blktap2_disk->ctl_socket_path);
        close(fd);
        return ERROR_FAIL;
    }

    blktap2_disk->fd = fd;
    return 0;
}

static void blktap2_colo_setup(libxl__checkpoint_device *dev)
{
    const libxl_device_disk *disk = dev->backend_dev;
    libxl__colo_blktap2_disk *blktap2_disk;
    int rc;
    char *type;
    int i, l;

    STATE_AO_GC(dev->cds->ao);

    if (disk->backend != LIBXL_DISK_BACKEND_TAP ||
        disk->format != LIBXL_DISK_FORMAT_COLO) {
        rc = ERROR_CHECKPOINT_DEVOPS_DOES_NOT_MATCH;
        goto out;
    }

    dev->matched = 1;
    GCNEW(blktap2_disk);
    dev->concrete_data = blktap2_disk;
    blktap2_disk->fd = -1;
    blktap2_disk->dev = dev;

    type = strchr(disk->pdev_path, '|');
    if (!type) {
        LOG(ERROR, "unexpected pdev_path: %s", disk->pdev_path);
        rc = ERROR_FAIL;
        goto out;
    }
    blktap2_disk->name = libxl__strndup(gc, disk->pdev_path,
                                        type - disk->pdev_path);
    blktap2_disk->ctl_socket_path = libxl__sprintf(gc, "%s/colo_%s",
                                                   BLKTAP_CTRL_DIR,
                                                   blktap2_disk->name);
    /* scrub socket pathname */
    l = strlen(blktap2_disk->ctl_socket_path);
    for (i = strlen(BLKTAP_CTRL_DIR) + 1; i < l; i++) {
        if (strchr(":/", blktap2_disk->ctl_socket_path[i]))
            blktap2_disk->ctl_socket_path[i] = '_';
    }

    libxl__ev_fd_init(&blktap2_disk->ev);

    rc = blktap2_control_connect(gc, blktap2_disk);

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(dev->cds->egc, &dev->aodev);
}

static void blktap2_colo_teardown(libxl__checkpoint_device *dev)
{
    libxl__colo_blktap2_disk *blktap2_disk = dev->concrete_data;

    if (blktap2_disk->fd > 0) {
        close(blktap2_disk->fd);
        blktap2_disk->fd = -1;
    }

    dev->aodev.rc = 0;
    dev->aodev.callback(dev->cds->egc, &dev->aodev);
}

/* ========== checkpointing APIs ========== */
static void blktap2_control_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                     int fd, short events, short revents);

static void blktap2_colo_postsuspend(libxl__checkpoint_device *dev)
{
    int ret;
    libxl__colo_blktap2_disk *blktap2_disk = dev->concrete_data;
    int rc = 0;

    /* unit socket fd, so not block */
    ret = write(blktap2_disk->fd, BLKTAP2_REQUEST, strlen(BLKTAP2_REQUEST));
    if (ret < strlen(BLKTAP2_REQUEST))
        rc = ERROR_FAIL;

    dev->aodev.rc = rc;
    dev->aodev.callback(dev->cds->egc, &dev->aodev);
}

static void blktap2_colo_commit(libxl__checkpoint_device *dev)
{
    libxl__colo_blktap2_disk *blktap2_disk = dev->concrete_data;
    int rc;

    /* Convenience aliases */
    const int fd = blktap2_disk->fd;
    libxl__ev_fd *const ev = &blktap2_disk->ev;

    STATE_AO_GC(dev->cds->ao);

    rc = libxl__ev_fd_register(gc, ev, blktap2_control_readable, fd, POLLIN);
    if (rc) {
        dev->aodev.rc = rc;
        dev->aodev.callback(dev->cds->egc, &dev->aodev);
    }
}

static void blktap2_control_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                     int fd, short events, short revents)
{
    libxl__colo_blktap2_disk *blktap2_disk =
                CONTAINER_OF(ev, *blktap2_disk, ev);
    int rc = 0, ret;
    char response[5];

    /* Convenience aliases */
    libxl__checkpoint_device *const dev = blktap2_disk->dev;

    EGC_GC;

    libxl__ev_fd_deregister(gc, ev);

    if (revents & ~POLLIN) {
        LOG(ERROR, "unexpected poll event 0x%x (should be POLLIN)", revents);
        rc = ERROR_FAIL;
        goto out;
    }

    ret = read(blktap2_disk->fd, response, sizeof(response) - 1);
    if (ret < sizeof(response) - 1) {
        rc = ERROR_FAIL;
        goto out;
    }

    response[4] = '\0';
    if (strcmp(response, BLKTAP2_RESPONSE))
        rc = ERROR_FAIL;

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(dev->cds->egc, &dev->aodev);
}

const libxl__checkpoint_device_instance_ops colo_save_device_blktap2_disk = {
    .kind = LIBXL__DEVICE_KIND_CHECKPOINT_DISK,
    .setup = blktap2_colo_setup,
    .teardown = blktap2_colo_teardown,
    .postsuspend = blktap2_colo_postsuspend,
    .commit = blktap2_colo_commit,
};
