/*
 * Copyright (C) 2014
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

/*----- helper functions -----*/

static int init_device_subkind(libxl__checkpoint_device_state *cds)
{
    int rc;
    const libxl__checkpoint_device_subkind_ops **ops;

    for (ops = cds->ops; *ops; ops++) {
        rc = (*ops)->init(cds);
        if (rc) {
            goto out;
        }
    }

    rc = 0;
out:
    return rc;

}

static void destroy_device_subkind(libxl__checkpoint_device_state *cds)
{
    const libxl__checkpoint_device_subkind_ops **ops;

    for (ops = cds->ops; *ops; ops++)
        (*ops)->destroy(cds);
}

static bool all_devices_handled(libxl__checkpoint_device_state *cds)
{
    return cds->num_devices == (cds->num_nics + cds->num_disks);
}

/*----- setup() and teardown() -----*/

/* callbacks */

static void device_match_cb(libxl__egc *egc,
                            libxl__checkpoint_device *dev,
                            int rc);
static void device_setup_cb(libxl__egc *egc,
                            libxl__checkpoint_device *dev,
                            int rc);
static void device_teardown_cb(libxl__egc *egc,
                               libxl__checkpoint_device *dev,
                               int rc);

/* checkpoint device setup and teardown */

static void libxl__checkpoint_device_init(libxl__egc *egc,
                                     libxl__checkpoint_device_state *cds,
                                     libxl__checkpoint_device_kind kind,
                                     void *libxl_dev);
void libxl__checkpoint_devices_setup(libxl__egc *egc, libxl__checkpoint_device_state *cds)
{
    int i;
    STATE_AO_GC(cds->ao);

    if (!cds->ops[0])
        goto out;

    cds->saved_rc = init_device_subkind(cds);
    if (cds->saved_rc)
        goto out;

    cds->num_devices = 0;
    cds->num_nics = 0;
    cds->num_disks = 0;

    if (cds->enabled_device_kinds & LIBXL__CHECKPOINT_DEVICE_NIC)
        cds->nics = libxl_device_nic_list(CTX, cds->domid, &cds->num_nics);

    if (cds->enabled_device_kinds & LIBXL__CHECKPOINT_DEVICE_NIC)
        cds->disks = libxl_device_disk_list(CTX, cds->domid, &cds->num_disks);

    if (cds->num_nics == 0 && cds->num_disks == 0)
        goto out;

    GCNEW_ARRAY(cds->dev, cds->num_nics + cds->num_disks);

    for (i = 0; i < cds->num_nics; i++) {
        libxl__checkpoint_device_init(egc, cds,
                                 LIBXL__CHECKPOINT_DEVICE_NIC, &cds->nics[i]);
    }

    for (i = 0; i < cds->num_disks; i++) {
        libxl__checkpoint_device_init(egc, cds,
                                 LIBXL__CHECKPOINT_DEVICE_DISK, &cds->disks[i]);
    }

    return;

out:
    cds->callback(egc, cds, cds->saved_rc);
    return;
}

static void libxl__checkpoint_device_init(libxl__egc *egc,
                                     libxl__checkpoint_device_state *cds,
                                     libxl__checkpoint_device_kind kind,
                                     void *libxl_dev)
{
    libxl__checkpoint_device *dev = NULL;

    STATE_AO_GC(cds->ao);
    GCNEW(dev);
    dev->backend_dev = libxl_dev;
    dev->kind = kind;
    dev->cds = cds;

    libxl__async_exec_init(&dev->aes);
    libxl__ev_child_init(&dev->child);

    /* match the ops begin */
    dev->ops_index = 0;
    dev->ops = cds->ops[dev->ops_index];
    for (; dev->ops; dev->ops = cds->ops[++dev->ops_index]) {
        if (dev->ops->kind == dev->kind) {
            if (dev->ops->match) {
                dev->callback = device_match_cb;
                dev->ops->match(dev);
            } else {
                /*
                 * This devops do not have match() implementation.
                 * That means this *kind* of device's ops is always
                 * matched with the *kind* of device.
                 */
                dev->callback = device_setup_cb;
                dev->ops->setup(dev);
            }
            break;
        }
    }

    if (!dev->ops) {
        cds->num_devices++;
        cds->saved_rc = ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED;
        if (all_devices_handled(cds))
            cds->callback(egc, cds, cds->saved_rc);
    }
}

static void device_match_cb(libxl__egc *egc,
                            libxl__checkpoint_device *dev,
                            int rc)
{
    libxl__checkpoint_device_state *const cds = dev->cds;

    STATE_AO_GC(cds->ao);

    if (cds->saved_rc) {
        /* there's already an error happened, we do not need to continue */
        cds->num_devices++;
        if (all_devices_handled(cds))
            cds->callback(egc, cds, cds->saved_rc);
        return;
    }

    if (rc) {
        /* the ops does not match, try next ops */
        dev->ops = cds->ops[++dev->ops_index];
        if (!dev->ops || rc != ERROR_CHECKPOINT_DEVOPS_NOT_MATCH) {
            /* the device can not be matched */
            cds->num_devices++;
            cds->saved_rc = ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED;
            if (all_devices_handled(cds))
                cds->callback(egc, cds, cds->saved_rc);
            return;
        }
        for ( ; dev->ops; dev->ops = cds->ops[++dev->ops_index]) {
            if (dev->ops->kind == dev->kind) {
                /*
                 * we have entered match process, that means this *kind* of
                 * device's ops must have a match() implementation.
                 */
                assert(dev->ops->match);
                dev->ops->match(dev);
                break;
            }
        }
    } else {
        /* the ops matched, setup the device */
        dev->callback = device_setup_cb;
        dev->ops->setup(dev);
    }
}

static void device_setup_cb(libxl__egc *egc,
                            libxl__checkpoint_device *dev,
                            int rc)
{
    /* Convenience aliases */
    libxl__checkpoint_device_state *const cds = dev->cds;

    STATE_AO_GC(cds->ao);

    cds->num_devices++;
    /*
     * the netbuf script was designed as below:
     * 1. when setup failed, the script won't teardown the device itself.
     * 2. the teardown op is ok to be executed many times.
     *
     * we add devices that have been set up to the array no matter
     * the setup process succeed or failed because we need to ensure
     * the device been teardown while setup failed. If any of the
     * device setup failed, we will quit checkpoint, but before we exit,
     * we will teardown the devices that have been added to **dev
     */
    cds->dev[cds->num_set_up++] = dev;
    /* we preserve the first error that happened */
    if (rc && !cds->saved_rc)
        cds->saved_rc = rc;

    if (all_devices_handled(cds))
        cds->callback(egc, cds, cds->saved_rc);
}

void libxl__checkpoint_devices_teardown(libxl__egc *egc, libxl__checkpoint_device_state *cds)
{
    int i, num_set_up;
    libxl__checkpoint_device *dev;

    STATE_AO_GC(cds->ao);

    cds->saved_rc = 0;

    if (cds->num_set_up == 0) {
        destroy_device_subkind(cds);
        goto out;
    }

    /* we will decrease cds->num_set_up in the teardown callback */
    num_set_up = cds->num_set_up;
    for (i = 0; i < num_set_up; i++) {
        dev = cds->dev[i];
        dev->callback = device_teardown_cb;
        dev->ops->teardown(dev);
    }

    return;

out:
    cds->callback(egc, cds, cds->saved_rc);
    return;
}

static void device_teardown_cb(libxl__egc *egc,
                               libxl__checkpoint_device *dev,
                               int rc)
{
    int i;
    libxl__checkpoint_device_state *const cds = dev->cds;

    STATE_AO_GC(cds->ao);

    /* we preserve the first error that happened */
    if (rc && !cds->saved_rc)
        cds->saved_rc = rc;

    /* ignore teardown errors to teardown as many devs as possible*/
    cds->num_set_up--;

    if (cds->num_set_up == 0) {
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

        destroy_device_subkind(cds);
        cds->callback(egc, cds, cds->saved_rc);
    }
}

/*----- checkpointing APIs -----*/

/* callbacks */

static void device_checkpoint_cb(libxl__egc *egc,
                                 libxl__checkpoint_device *dev,
                                 int rc);

/* API implementations */

#define define_checkpoint_device_api(api)                             \
void libxl__checkpoint_devices_##api(libxl__egc *egc,                            \
                                libxl__checkpoint_device_state *cds)             \
{                                                                           \
    int i;                                                                  \
    libxl__checkpoint_device *dev;                                               \
                                                                            \
    STATE_AO_GC(cds->ao);                                                   \
                                                                            \
    cds->num_devices = 0;                                                   \
    cds->saved_rc = 0;                                                      \
                                                                            \
    if (cds->num_set_up == 0)                                               \
        goto out;                                                           \
                                                                            \
    for (i = 0; i < cds->num_set_up; i++) {                                 \
        dev = cds->dev[i];                                                  \
        dev->callback = device_checkpoint_cb;                               \
        if (dev->ops->api) {                                                \
            dev->ops->api(dev);                                             \
        } else {                                                            \
            cds->num_devices++;                                             \
            if (cds->num_devices == cds->num_set_up)                        \
                cds->callback(egc, cds, cds->saved_rc);                     \
        }                                                                   \
    }                                                                       \
                                                                            \
    return;                                                                 \
                                                                            \
out:                                                                        \
    cds->callback(egc, cds, cds->saved_rc);                                 \
}

define_checkpoint_device_api(postsuspend);

define_checkpoint_device_api(preresume);

define_checkpoint_device_api(commit);

static void device_checkpoint_cb(libxl__egc *egc,
                                 libxl__checkpoint_device *dev,
                                 int rc)
{
    /* Convenience aliases */
    libxl__checkpoint_device_state *const cds = dev->cds;

    STATE_AO_GC(cds->ao);

    cds->num_devices++;

    if (rc)
        cds->saved_rc = ERROR_FAIL;

    if (cds->num_devices == cds->num_set_up)
        cds->callback(egc, cds, cds->saved_rc);
}
