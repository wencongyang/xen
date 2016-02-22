/*
 * Copyright (C) 2014 FUJITSU LIMITED
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *         Yang Hongyang <hongyang.yang@easystack.cn>
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
#include "libxl_colo.h"

static const libxl__checkpoint_device_instance_ops *colo_ops[] = {
    NULL,
};

/* ================= helper functions ================= */
static int init_device_subkind(libxl__checkpoint_devices_state *cds)
{
    /* init device subkind-specific state in the libxl ctx */
    int rc;
    STATE_AO_GC(cds->ao);

    rc = 0;
    return rc;
}

static void cleanup_device_subkind(libxl__checkpoint_devices_state *cds)
{
    /* cleanup device subkind-specific state in the libxl ctx */
    STATE_AO_GC(cds->ao);
}

/* ================= colo: setup save environment ================= */
static void colo_save_setup_done(libxl__egc *egc,
                                 libxl__checkpoint_devices_state *cds,
                                 int rc);
static void colo_save_setup_failed(libxl__egc *egc,
                                   libxl__checkpoint_devices_state *cds,
                                   int rc);
static void libxl__colo_save_domain_suspend_callback(void *data);
static void libxl__colo_save_domain_checkpoint_callback(void *data);
static void libxl__colo_save_domain_resume_callback(void *data);
static void libxl__colo_save_domain_wait_checkpoint_callback(void *data);

void libxl__colo_save_setup(libxl__egc *egc, libxl__colo_save_state *css)
{
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;
    libxl__srm_save_autogen_callbacks *const callbacks =
        &dss->sws.shs.callbacks.save.a;

    STATE_AO_GC(dss->ao);

    if (dss->type != LIBXL_DOMAIN_TYPE_HVM) {
        LOG(ERROR, "COLO only supports hvm now");
        goto out;
    }

    css->send_fd = dss->fd;
    css->recv_fd = dss->recv_fd;
    css->svm_running = false;

    /* TODO: disk/nic support */
    cds->device_kind_flags = 0;
    cds->ops = colo_ops;
    cds->callback = colo_save_setup_done;
    cds->ao = ao;
    cds->domid = dss->domid;
    cds->concrete_data = css;

    css->srs.ao = ao;
    css->srs.fd = css->recv_fd;
    css->srs.back_channel = true;
    libxl__stream_read_start(egc, &css->srs);

    if (init_device_subkind(cds))
        goto out;

    callbacks->suspend = libxl__colo_save_domain_suspend_callback;
    callbacks->postcopy = libxl__colo_save_domain_resume_callback;
    callbacks->checkpoint = libxl__colo_save_domain_checkpoint_callback;
    callbacks->wait_checkpoint = libxl__colo_save_domain_wait_checkpoint_callback;

    libxl__checkpoint_devices_setup(egc, &dss->cds);

    return;

out:
    libxl__ao_complete(egc, ao, ERROR_FAIL);
}

static void colo_save_setup_done(libxl__egc *egc,
                                 libxl__checkpoint_devices_state *cds,
                                 int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);
    EGC_GC;

    if (!rc) {
        libxl__domain_save(egc, dss);
        return;
    }

    LOG(ERROR, "COLO: failed to setup device for guest with domid %u",
        dss->domid);
    cds->callback = colo_save_setup_failed;
    libxl__checkpoint_devices_teardown(egc, cds);
}

static void colo_save_setup_failed(libxl__egc *egc,
                                   libxl__checkpoint_devices_state *cds,
                                   int rc)
{
    STATE_AO_GC(cds->ao);

    if (rc)
        LOG(ERROR, "COLO: failed to teardown device after setup failed"
            " for guest with domid %u, rc %d", cds->domid, rc);

    cleanup_device_subkind(cds);
    libxl__ao_complete(egc, ao, rc);
}


/* ================= colo: teardown save environment ================= */
static void colo_teardown_done(libxl__egc *egc,
                               libxl__checkpoint_devices_state *cds,
                               int rc);

void libxl__colo_save_teardown(libxl__egc *egc,
                               libxl__colo_save_state *css,
                               int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    LOG(WARN, "COLO: Domain suspend terminated with rc %d,"
        " teardown COLO devices...", rc);

    libxl__stream_read_abort(egc, &css->srs, 1);

    dss->cds.callback = colo_teardown_done;
    libxl__checkpoint_devices_teardown(egc, &dss->cds);
    return;
}

static void colo_teardown_done(libxl__egc *egc,
                               libxl__checkpoint_devices_state *cds,
                               int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    cleanup_device_subkind(cds);
    dss->callback(egc, dss, rc);
}

/*
 * checkpoint callbacks are called in the following order:
 * 1. suspend
 * 2. checkpoint
 * 3. resume
 * 4. wait checkpoint
 */
static void colo_common_write_stream_done(libxl__egc *egc,
                                          libxl__stream_write_state *stream,
                                          int rc);
static void colo_common_read_stream_done(libxl__egc *egc,
                                         libxl__stream_read_state *stream,
                                         int rc);
/* ===================== colo: suspend primary vm ===================== */

static void colo_read_svm_suspended_done(libxl__egc *egc,
                                         libxl__colo_save_state *css,
                                         int id);
/*
 * Do the following things when suspending primary vm:
 * 1. suspend primary vm
 * 2. do postsuspend
 * 3. read CHECKPOINT_SVM_SUSPENDED
 * 4. read secondary vm's dirty pages
 */
static void colo_suspend_primary_vm_done(libxl__egc *egc,
                                         libxl__domain_suspend_state *dsps,
                                         int ok);
static void colo_postsuspend_cb(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds,
                                int rc);

static void libxl__colo_save_domain_suspend_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__stream_write_state *sws = CONTAINER_OF(shs, *sws, shs);
    libxl__domain_save_state *dss = sws->dss;

    /* Convenience aliases */
    libxl__domain_suspend_state *dsps = &dss->dsps;

    dsps->callback_common_done = colo_suspend_primary_vm_done;
    libxl__domain_suspend(egc, dsps);
}

static void colo_suspend_primary_vm_done(libxl__egc *egc,
                                         libxl__domain_suspend_state *dsps,
                                         int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(dsps, *dss, dsps);

    EGC_GC;

    if (rc) {
        LOG(ERROR, "cannot suspend primary vm");
        goto out;
    }

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;

    cds->callback = colo_postsuspend_cb;
    libxl__checkpoint_devices_postsuspend(egc, cds);
    return;

out:
    dss->rc = rc;
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

static void colo_postsuspend_cb(libxl__egc *egc,
                                libxl__checkpoint_devices_state *cds,
                                int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (rc) {
        LOG(ERROR, "postsuspend fails");
        goto out;
    }

    if (!css->svm_running) {
        rc = 0;
        goto out;
    }

    /*
     * read CHECKPOINT_SVM_SUSPENDED
     */
    css->callback = colo_read_svm_suspended_done;
    css->srs.checkpoint_callback = colo_common_read_stream_done;
    libxl__stream_read_checkpoint_state(egc, &css->srs);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, !rc);
}

static void colo_read_svm_suspended_done(libxl__egc *egc,
                                         libxl__colo_save_state *css,
                                         int id)
{
    int ok = 0;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (id != CHECKPOINT_SVM_SUSPENDED) {
        LOG(ERROR, "invalid section: %d, expected: %d", id,
            CHECKPOINT_SVM_SUSPENDED);
        goto out;
    }

    ok = 1;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, ok);
}


/* ===================== colo: send tailbuf ========================== */
static void libxl__colo_save_domain_checkpoint_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__stream_write_state *sws = CONTAINER_OF(shs, *sws, shs);
    libxl__domain_save_state *dss = sws->dss;

    /* Convenience aliases */
    libxl__colo_save_state *const css = &dss->css;

    /* write emulator xenstore data, emulator context, and checkpoint end */
    css->callback = NULL;
    dss->sws.checkpoint_callback = colo_common_write_stream_done;
    libxl__stream_write_start_checkpoint(shs->egc, &dss->sws);
}

/* ===================== colo: resume primary vm ===================== */
/*
 * Do the following things when resuming primary vm:
 *  1. read CHECKPOINT_SVM_READY
 *  2. do preresume
 *  3. resume primary vm
 *  4. read CHECKPOINT_SVM_RESUMED
 */
static void colo_read_svm_ready_done(libxl__egc *egc,
                                     libxl__colo_save_state *css,
                                     int id);
static void colo_preresume_cb(libxl__egc *egc,
                              libxl__checkpoint_devices_state *cds,
                              int rc);
static void colo_read_svm_resumed_done(libxl__egc *egc,
                                       libxl__colo_save_state *css,
                                       int id);

static void libxl__colo_save_domain_resume_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__egc *egc = shs->egc;
    libxl__stream_write_state *sws = CONTAINER_OF(shs, *sws, shs);
    libxl__domain_save_state *dss = sws->dss;

    /* Convenience aliases */
    libxl__colo_save_state *const css = &dss->css;

    EGC_GC;

    /* read CHECKPOINT_SVM_READY */
    css->callback = colo_read_svm_ready_done;
    css->srs.checkpoint_callback = colo_common_read_stream_done;
    libxl__stream_read_checkpoint_state(egc, &css->srs);
}

static void colo_read_svm_ready_done(libxl__egc *egc,
                                     libxl__colo_save_state *css,
                                     int id)
{
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (id != CHECKPOINT_SVM_READY) {
        LOG(ERROR, "invalid section: %d, expected: %d", id,
            CHECKPOINT_SVM_READY);
        goto out;
    }

    css->svm_running = true;
    dss->cds.callback = colo_preresume_cb;
    libxl__checkpoint_devices_preresume(egc, &dss->cds);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void colo_preresume_cb(libxl__egc *egc,
                              libxl__checkpoint_devices_state *cds,
                              int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (rc) {
        LOG(ERROR, "preresume fails");
        goto out;
    }

    /* Resumes the domain and the device model */
    if (libxl__domain_resume(gc, dss->domid, /* Fast Suspend */1)) {
        LOG(ERROR, "cannot resume primary vm");
        goto out;
    }

    /* read CHECKPOINT_SVM_RESUMED */
    css->callback = colo_read_svm_resumed_done;
    css->srs.checkpoint_callback = colo_common_read_stream_done;
    libxl__stream_read_checkpoint_state(egc, &css->srs);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void colo_read_svm_resumed_done(libxl__egc *egc,
                                       libxl__colo_save_state *css,
                                       int id)
{
    int ok = 0;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (id != CHECKPOINT_SVM_RESUMED) {
        LOG(ERROR, "invalid section: %d, expected: %d", id,
            CHECKPOINT_SVM_RESUMED);
        goto out;
    }

    ok = 1;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, ok);
}


/* ===================== colo: wait new checkpoint ===================== */
/*
 * Do the following things:
 * 1. do commit
 * 2. wait for a new checkpoint
 * 3. write CHECKPOINT_NEW
 */
static void colo_device_commit_cb(libxl__egc *egc,
                                  libxl__checkpoint_devices_state *cds,
                                  int rc);
static void colo_start_new_checkpoint(libxl__egc *egc,
                                      libxl__checkpoint_devices_state *cds,
                                      int rc);

static void libxl__colo_save_domain_wait_checkpoint_callback(void *data)
{
    libxl__save_helper_state *shs = data;
    libxl__stream_write_state *sws = CONTAINER_OF(shs, *sws, shs);
    libxl__domain_save_state *dss = sws->dss;
    libxl__egc *egc = dss->sws.shs.egc;

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = &dss->cds;

    cds->callback = colo_device_commit_cb;
    libxl__checkpoint_devices_commit(egc, cds);
}

static void colo_device_commit_cb(libxl__egc *egc,
                                  libxl__checkpoint_devices_state *cds,
                                  int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);

    EGC_GC;

    if (rc) {
        LOG(ERROR, "commit fails");
        goto out;
    }

    /* TODO: wait a new checkpoint */
    colo_start_new_checkpoint(egc, cds, 0);
    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}

static void colo_start_new_checkpoint(libxl__egc *egc,
                                      libxl__checkpoint_devices_state *cds,
                                      int rc)
{
    libxl__colo_save_state *css = cds->concrete_data;
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);
    libxl_sr_checkpoint_state srcs = { .id = CHECKPOINT_NEW };

    if (rc)
        goto out;

    /* write CHECKPOINT_NEW */
    css->callback = NULL;
    dss->sws.checkpoint_callback = colo_common_write_stream_done;
    libxl__stream_write_checkpoint_state(egc, &dss->sws, &srcs);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, 0);
}


/* ===================== colo: common callback ===================== */
static void colo_common_write_stream_done(libxl__egc *egc,
                                          libxl__stream_write_state *stream,
                                          int rc)
{
    libxl__domain_save_state *dss = CONTAINER_OF(stream, *dss, sws);
    int ok;

    /* Convenience aliases */
    libxl__colo_save_state *const css = &dss->css;

    EGC_GC;

    if (rc < 0) {
        /* TODO: it may be a internal error, but we don't know */
        LOG(ERROR, "sending data fails");
        ok = 0;
        goto out;
    }

    if (!css->callback) {
        /* Everythins is OK */
        ok = 1;
        goto out;
    }

    css->callback(egc, css, 0);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, ok);
}

static void colo_common_read_stream_done(libxl__egc *egc,
                                         libxl__stream_read_state *stream,
                                         int rc)
{
    libxl__colo_save_state *css = CONTAINER_OF(stream, *css, srs);
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);
    int ok;

    EGC_GC;

    if (rc < 0) {
        /* TODO: it may be a internal error, but we don't know */
        LOG(ERROR, "reading data fails");
        ok = 0;
        goto out;
    }

    if (!css->callback) {
        /* Everythins is OK */
        ok = 1;
        goto out;
    }

    /* rc contains the id */
    css->callback(egc, css, rc);

    return;

out:
    libxl__xc_domain_saverestore_async_callback_done(egc, &dss->sws.shs, ok);
}
