/*
 * Copyright (C) 2014 FUJITSU LIMITED
 * Author: Yang Hongyang <yanghy@cn.fujitsu.com>
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

extern const libxl__checkpoint_device_instance_ops remus_device_nic;
extern const libxl__checkpoint_device_instance_ops remus_device_drbd_disk;
static const libxl__checkpoint_device_instance_ops *remus_ops[] = {
    &remus_device_nic,
    &remus_device_drbd_disk,
    NULL,
};

/*----- helper functions -----*/

static int init_device_subkind(libxl__checkpoint_devices_state *cds)
{
    /* init device subkind-specific state in the libxl ctx */
    int rc;
    STATE_AO_GC(cds->ao);

    if (libxl__netbuffer_enabled(gc)) {
        rc = init_subkind_nic(cds);
        if (rc) goto out;
    }

    rc = init_subkind_drbd_disk(cds);
    if (rc) goto out;

    rc = 0;
out:
    return rc;
}

static void cleanup_device_subkind(libxl__checkpoint_devices_state *cds)
{
    /* cleanup device subkind-specific state in the libxl ctx */
    STATE_AO_GC(cds->ao);

    if (libxl__netbuffer_enabled(gc))
        cleanup_subkind_nic(cds);

    cleanup_subkind_drbd_disk(cds);
}

/*----- setup() and teardown() -----*/

/* callbacks */

static void devices_setup_cb(libxl__egc *egc,
                             libxl__multidev *multidev,
                             int rc);
static void devices_teardown_cb(libxl__egc *egc,
                                libxl__multidev *multidev,
                                int rc);

/* checkpoint device setup and teardown */

static libxl__checkpoint_device* checkpoint_device_init(libxl__egc *egc,
                                              libxl__checkpoint_devices_state *cds,
                                              libxl__device_kind kind,
                                              void *libxl_dev)
{
    libxl__checkpoint_device *dev = NULL;

    STATE_AO_GC(cds->ao);
    GCNEW(dev);
    dev->backend_dev = libxl_dev;
    dev->kind = kind;
    dev->cds = cds;
    dev->ops_index = -1;

    return dev;
}

static void checkpoint_devices_setup(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds);

void libxl__checkpoint_devices_setup(libxl__egc *egc, libxl__checkpoint_devices_state *cds)
{
    int i, rc;

    STATE_AO_GC(cds->ao);

    rc = init_device_subkind(cds);
    if (rc)
        goto out;

    cds->num_devices = 0;
    cds->num_nics = 0;
    cds->num_disks = 0;

    if (cds->device_kind_flags & (1 << LIBXL__DEVICE_KIND_CHECKPOINT_NIC))
        cds->nics = libxl_device_nic_list(CTX, cds->domid, &cds->num_nics);

    if (cds->device_kind_flags & (1 << LIBXL__DEVICE_KIND_CHECKPOINT_DISK))
        cds->disks = libxl_device_disk_list(CTX, cds->domid, &cds->num_disks);

    if (cds->num_nics == 0 && cds->num_disks == 0)
        goto out;

    GCNEW_ARRAY(cds->devs, cds->num_nics + cds->num_disks);

    for (i = 0; i < cds->num_nics; i++) {
        cds->devs[cds->num_devices++] = checkpoint_device_init(egc, cds,
                                                LIBXL__DEVICE_KIND_CHECKPOINT_NIC,
                                                &cds->nics[i]);
    }

    for (i = 0; i < cds->num_disks; i++) {
        cds->devs[cds->num_devices++] = checkpoint_device_init(egc, cds,
                                                LIBXL__DEVICE_KIND_CHECKPOINT_DISK,
                                                &cds->disks[i]);
    }

    checkpoint_devices_setup(egc, cds);

    return;

out:
    cds->callback(egc, cds, rc);
}

static void checkpoint_devices_setup(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds)
{
    int i, rc;
    libxl__checkpoint_device *dev;

    STATE_AO_GC(cds->ao);

    libxl__multidev_begin(ao, &cds->multidev);
    cds->multidev.callback = devices_setup_cb;
    for (i = 0; i < cds->num_devices; i++) {
        dev = cds->devs[i];
        if (dev->matched)
            continue;

        /* find avaliable ops */
        do {
            dev->ops = remus_ops[++dev->ops_index];
            if (!dev->ops) {
                rc = ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED;
                goto out;
            }
        } while (dev->ops->kind != dev->kind);

        libxl__multidev_prepare_with_aodev(&cds->multidev, &dev->aodev);
        dev->ops->setup(dev);
    }

    rc = 0;
out:
    libxl__multidev_prepared(egc, &cds->multidev, rc);
}

static void devices_setup_cb(libxl__egc *egc,
                             libxl__multidev *multidev,
                             int rc)
{
    STATE_AO_GC(multidev->ao);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds =
                            CONTAINER_OF(multidev, *cds, multidev);

    /*
     * if the error is ERROR_CHECKPOINT_DEVOPS_DOES_NOT_MATCH, begin next iter
     * if there are devices that can't be set up, the rc will become
     * ERROR_FAIL or ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED at last anyway.
     */
    if (rc == ERROR_CHECKPOINT_DEVOPS_DOES_NOT_MATCH) {
        checkpoint_devices_setup(egc, cds);
        return;
    }

    cds->callback(egc, cds, rc);
}

void libxl__checkpoint_devices_teardown(libxl__egc *egc,
                                   libxl__checkpoint_devices_state *cds)
{
    int i;
    libxl__checkpoint_device *dev;

    STATE_AO_GC(cds->ao);

    libxl__multidev_begin(ao, &cds->multidev);
    cds->multidev.callback = devices_teardown_cb;
    for (i = 0; i < cds->num_devices; i++) {
        dev = cds->devs[i];
        if (!dev->ops || !dev->matched)
            continue;

        libxl__multidev_prepare_with_aodev(&cds->multidev, &dev->aodev);
        dev->ops->teardown(dev);
    }

    libxl__multidev_prepared(egc, &cds->multidev, 0);
}

static void devices_teardown_cb(libxl__egc *egc,
                                libxl__multidev *multidev,
                                int rc)
{
    int i;

    STATE_AO_GC(multidev->ao);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds =
                            CONTAINER_OF(multidev, *cds, multidev);

    /* clean nic */
    for (i = 0; i < cds->num_nics; i++)
        libxl_device_nic_dispose(&cds->nics[i]);
    free(cds->nics);
    cds->nics = NULL;
    cds->num_nics = 0;

    /* clean disk */
    for (i = 0; i < cds->num_disks; i++)
        libxl_device_disk_dispose(&cds->disks[i]);
    free(cds->disks);
    cds->disks = NULL;
    cds->num_disks = 0;

    cleanup_device_subkind(cds);

    cds->callback(egc, cds, rc);
}

/*----- checkpointing APIs -----*/

/* callbacks */

static void devices_checkpoint_cb(libxl__egc *egc,
                                  libxl__multidev *multidev,
                                  int rc);

/* API implementations */

#define define_checkpoint_api(api)                                \
void libxl__checkpoint_devices_##api(libxl__egc *egc,                        \
                                libxl__checkpoint_devices_state *cds)        \
{                                                                       \
    int i;                                                              \
    libxl__checkpoint_device *dev;                                           \
                                                                        \
    STATE_AO_GC(cds->ao);                                               \
                                                                        \
    libxl__multidev_begin(ao, &cds->multidev);                          \
    cds->multidev.callback = devices_checkpoint_cb;                     \
    for (i = 0; i < cds->num_devices; i++) {                            \
        dev = cds->devs[i];                                             \
        if (!dev->matched || !dev->ops->api)                            \
            continue;                                                   \
        libxl__multidev_prepare_with_aodev(&cds->multidev, &dev->aodev);\
        dev->ops->api(dev);                                             \
    }                                                                   \
                                                                        \
    libxl__multidev_prepared(egc, &cds->multidev, 0);                   \
}

define_checkpoint_api(postsuspend);

define_checkpoint_api(preresume);

define_checkpoint_api(commit);

static void devices_checkpoint_cb(libxl__egc *egc,
                                  libxl__multidev *multidev,
                                  int rc)
{
    STATE_AO_GC(multidev->ao);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds =
                            CONTAINER_OF(multidev, *cds, multidev);

    cds->callback(egc, cds, rc);
}
