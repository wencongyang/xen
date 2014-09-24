/*
 * Copyright (C) 2010      Advanced Micro Devices
 * Author Christoph Egger <Christoph.Egger@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxl_internal.h"

#include "tap-ctl.h"

int libxl__blktap_enabled(libxl__gc *gc)
{
    const char *msg;
    return !tap_ctl_check(&msg);
}

char *libxl__blktap_devpath(libxl__gc *gc,
                            const char *disk,
                            libxl_disk_format format,
                            const char *filter,
                            const char *filter_params)
{
    const char *type, *disk_params;
    char *params, *devname = NULL;
    tap_list_t tap;
    int err;

    type = libxl__device_disk_string_of_format(format);
    if (!type)
        return NULL;

    if (filter) {
        disk_params = libxl__sprintf(gc, "%s|%s:%s", filter_params, type, disk);
        type = filter;
    } else {
        disk_params = disk;
    }
    err = tap_ctl_find(type, disk_params, &tap);
    if (err == 0) {
        devname = libxl__sprintf(gc, "/dev/xen/blktap-2/tapdev%d", tap.minor);
        if (devname)
            return devname;
    }

    params = libxl__sprintf(gc, "%s:%s", type, disk_params);
    err = tap_ctl_create(params, &devname);
    if (!err) {
        libxl__ptr_add(gc, devname);
        return devname;
    }

    return NULL;
}


int libxl__device_destroy_tapdisk(libxl__gc *gc,
                                  const char *params,
                                  const char *filter_params)
{
    char *type, *disk;
    int err, rc;
    tap_list_t tap;
    libxl_disk_format format;

    type = libxl__strdup(gc, params);

    disk = strchr(type, ':');
    if (!disk) {
        LOG(ERROR, "Unable to parse params %s", params);
        return ERROR_INVAL;
    }

    *disk++ = '\0';

    /* type may be raw */
    rc = libxl_disk_format_from_string(type, &format);
    if (rc < 0) {
        LOG(ERROR, "invalid disk type %s", type);
        return rc;
    }

    type = libxl__device_disk_string_of_format(format);

    if (filter_params) {
        char *tmp;
        char *tmp_type = type, *tmp_disk = disk;

        type = libxl__strdup(gc, filter_params);
        tmp = strchr(type, ':');

        if (!tmp) {
            LOG(ERROR, "Unable to parse filter-params %s", filter_params);
            return ERROR_FAIL;
        }
        *tmp++ = '\0';
        disk = libxl__sprintf(gc, "%s|%s:%s", tmp, tmp_type, tmp_disk);
    }

    err = tap_ctl_find(type, disk, &tap);
    if (err < 0) {
        /* returns -errno */
        LOGEV(ERROR, -err, "Unable to find type %s disk %s", type, disk);
        return ERROR_FAIL;
    }

    err = tap_ctl_destroy(tap.id, tap.minor);
    if (err < 0) {
        LOGEV(ERROR, -err, "Failed to destroy tap device id %d minor %d",
              tap.id, tap.minor);
        return ERROR_FAIL;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
