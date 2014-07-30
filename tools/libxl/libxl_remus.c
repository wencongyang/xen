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
#include "libxl_remus.h"


/*----- remus: setup the environment -----*/
static void libxl__remus_setup_done(libxl__egc *egc,
                                    libxl__checkpoint_devices_state *cds,
                                    int rc);
static void libxl__remus_setup_failed(libxl__egc *egc,
                                      libxl__checkpoint_devices_state *cds,
                                      int rc);

void libxl__remus_setup(libxl__egc *egc,
                        libxl__domain_suspend_state *dss)
{
    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;
    const libxl_domain_remus_info *const info = dss->remus;

    STATE_AO_GC(dss->ao);

    if (info->netbuf) {
        if (!libxl__netbuffer_enabled(gc)) {
            LOG(ERROR, "Remus: No support for network buffering");
            goto out;
        }
        cds->device_kind_flags |= LIBXL__CHECKPOINT_DEVICE_NIC;
    }

    if (info->diskbuf)
        cds->device_kind_flags |= LIBXL__CHECKPOINT_DEVICE_DISK;

    cds->ao = ao;
    cds->egc = egc;
    cds->domid = dss->domid;
    cds->callback = libxl__remus_setup_done;

    libxl__checkpoint_devices_setup(egc, cds);
    return;

out:
    libxl__remus_setup_failed(egc, cds, ERROR_FAIL);
}

static void libxl__remus_setup_done(libxl__egc *egc,
                                    libxl__checkpoint_devices_state *cds,
                                    int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(cds, *dss, cds);
    STATE_AO_GC(dss->ao);

    if (!rc) {
        libxl__domain_suspend(egc, dss);
        return;
    }

    LOG(ERROR, "Remus: failed to setup device for guest with domid %u, rc %d",
        dss->domid, rc);
    cds->callback = libxl__remus_setup_failed;
    libxl__checkpoint_devices_teardown(egc, cds);
}

static void libxl__remus_setup_failed(libxl__egc *egc,
                                      libxl__checkpoint_devices_state *cds,
                                      int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(cds, *dss, cds);
    STATE_AO_GC(dss->ao);

    if (rc)
        LOG(ERROR, "Remus: failed to teardown device after setup failed"
            " for guest with domid %u, rc %d", dss->domid, rc);

    dss->callback(egc, dss, rc);
}


/*----- remus: teardown the environment -----*/
static void remus_teardown_done(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds,
                                int rc);

void libxl__remus_teardown(libxl__egc *egc,
                           libxl__domain_suspend_state *dss,
                           int rc)
{
    EGC_GC;

    /*
     * If we reach this point, it means either backup died or some
     * network error occurred preventing us from sending checkpoints.
     * Teardown the network buffers and release netlink resources.
     * This is an async op.
     */
    LOG(WARN, "Remus: Domain suspend terminated with rc %d,"
        " teardown Remus devices...", rc);
    dss->cds.callback = remus_teardown_done;
    libxl__checkpoint_devices_teardown(egc, &dss->cds);
}

static void remus_teardown_done(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds,
                                int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(cds, *dss, cds);
    STATE_AO_GC(dss->ao);

    if (rc)
        LOG(ERROR, "Remus: failed to teardown device for guest with domid %u,"
            " rc %d", dss->domid, rc);

    dss->callback(egc, dss, rc);
}


/*----- remus: suspend the guest -----*/
static void remus_domain_suspend_callback_common_done(libxl__egc *egc,
                                libxl__domain_suspend_state2 *dss2, int ok);
static void remus_devices_postsuspend_cb(libxl__egc *egc,
                                         libxl__checkpoint_devices_state *cds,
                                         int rc);

void libxl__remus_domain_suspend_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__domain_suspend_state *dss = CONTAINER_OF(shs, *dss, shs);

    /* Convenience aliases */
    libxl__domain_suspend_state2 *const dss2 = &dss->dss2;

    dss2->callback_common_done = remus_domain_suspend_callback_common_done;
    libxl__domain_suspend2(egc, dss2);
}

static void remus_domain_suspend_callback_common_done(libxl__egc *egc,
                                libxl__domain_suspend_state2 *dss2, int ok)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(dss2, *dss, dss2);

    if (!ok)
        goto out;

    libxl__checkpoint_devices_state *const cds = &dss->cds;
    cds->callback = remus_devices_postsuspend_cb;
    libxl__checkpoint_devices_postsuspend(egc, cds);
    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->shs, ok);
}

static void remus_devices_postsuspend_cb(libxl__egc *egc,
                                         libxl__checkpoint_devices_state *cds,
                                         int rc)
{
    int ok = 0;
    libxl__domain_suspend_state *dss = CONTAINER_OF(cds, *dss, cds);

    if (rc)
        goto out;

    ok = 1;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->shs, ok);
}


/*----- remus: resume the guest -----*/
static void remus_devices_preresume_cb(libxl__egc *egc,
                                       libxl__checkpoint_devices_state *cds,
                                       int rc);

void libxl__remus_domain_resume_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__domain_suspend_state *dss = CONTAINER_OF(shs, *dss, shs);
    STATE_AO_GC(dss->ao);

    libxl__checkpoint_devices_state *const cds = &dss->cds;
    cds->callback = remus_devices_preresume_cb;
    libxl__checkpoint_devices_preresume(egc, cds);
}

static void remus_devices_preresume_cb(libxl__egc *egc,
                                       libxl__checkpoint_devices_state *cds,
                                       int rc)
{
    int ok = 0;
    libxl__domain_suspend_state *dss = CONTAINER_OF(cds, *dss, cds);
    STATE_AO_GC(dss->ao);

    if (rc)
        goto out;

    /* Resumes the domain and the device model */
    if (!libxl__domain_resume(gc, dss->domid, /* Fast Suspend */1, 0))
        ok = 1;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->shs, ok);
}


/*----- remus: wait a new checkpoint -----*/
static void remus_checkpoint_dm_saved(libxl__egc *egc,
                                      libxl__domain_suspend_state *dss,
                                      int rc);
static void remus_devices_commit_cb(libxl__egc *egc,
                                    libxl__checkpoint_devices_state *cds,
                                    int rc);
static void remus_next_checkpoint(libxl__egc *egc, libxl__ev_time *ev,
                                  const struct timeval *requested_abs);

void libxl__remus_domain_checkpoint_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__domain_suspend_state *dss = CONTAINER_OF(shs, *dss, shs);
    libxl__egc *egc = dss->shs.egc;
    STATE_AO_GC(dss->ao);

    /* This would go into tailbuf. */
    if (dss->hvm) {
        libxl__domain_save_device_model(egc, dss, remus_checkpoint_dm_saved);
    } else {
        remus_checkpoint_dm_saved(egc, dss, 0);
    }
}

static void remus_checkpoint_dm_saved(libxl__egc *egc,
                                      libxl__domain_suspend_state *dss, int rc)
{
    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;

    STATE_AO_GC(dss->ao);

    if (rc) {
        LOG(ERROR, "Failed to save device model. Terminating Remus..");
        goto out;
    }

    cds->callback = remus_devices_commit_cb;
    libxl__checkpoint_devices_commit(egc, cds);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->shs, 0);
}

static void remus_devices_commit_cb(libxl__egc *egc,
                                    libxl__checkpoint_devices_state *cds,
                                    int rc)
{
    libxl__domain_suspend_state *dss = CONTAINER_OF(cds, *dss, cds);

    STATE_AO_GC(dss->ao);

    if (rc) {
        LOG(ERROR, "Failed to do device commit op."
            " Terminating Remus..");
        goto out;
    }

    /*
     * At this point, we have successfully checkpointed the guest and
     * committed it at the backup. We'll come back after the checkpoint
     * interval to checkpoint the guest again. Until then, let the guest
     * continue execution.
     */

    /* Set checkpoint interval timeout */
    rc = libxl__ev_time_register_rel(gc, &dss->checkpoint_timeout,
                                     remus_next_checkpoint,
                                     dss->interval);

    if (rc) {
        LOG(ERROR, "unable to register timeout for next epoch."
            " Terminating Remus..");
        goto out;
    }

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->shs, 0);
}

static void remus_next_checkpoint(libxl__egc *egc, libxl__ev_time *ev,
                                  const struct timeval *requested_abs)
{
    libxl__domain_suspend_state *dss =
                            CONTAINER_OF(ev, *dss, checkpoint_timeout);

    STATE_AO_GC(dss->ao);

    /*
     * Time to checkpoint the guest again. We return 1 to libxc
     * (xc_domain_save.c). in order to continue executing the infinite loop
     * (suspend, checkpoint, resume) in xc_domain_save().
     */
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->shs, 1);
}
