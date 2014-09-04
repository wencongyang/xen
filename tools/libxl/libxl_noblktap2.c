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

int libxl__blktap_enabled(libxl__gc *gc)
{
    return 0;
}

char *libxl__blktap_devpath(libxl__gc *gc,
                            const char *disk,
                            libxl_disk_format format)
{
    return NULL;
}

int libxl__device_destroy_tapdisk(libxl__gc *gc, const char *params)
{
    return 0;
}

libxl_disk_format libxl__blktap_get_real_format(const char *disk,
                                                libxl_disk_format format)
{
    return format;
}

static int blktap2_colo_init(libxl__checkpoint_device *cds)
{
    return 0;
}

static void blktap2_colo_cleanup(libxl__checkpoint_device *cds)
{
    return;
}

static void blktap2_colo_setup(libxl__checkpoint_device *cds)
{
    dev->aodev.rc = ERROR_FAIL;
    dev->aodev.callback(dev->cds->egc, &dev->aodev);
}

static void blktap2_colo_teardown(libxl__checkpoint_device *cds)
{
    return;
}

const libxl__checkpoint_device_instance_ops colo_save_device_blktap2_disk = {
    .kind = LIBXL__CHECKPOINT_DEVICE_DISK,
    .init = blktap2_colo_init,
    .cleanup = blktap2_colo_cleanup,
    .setup = blktap2_colo_setup,
    .teardown = blktap2_colo_teardown,
};

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
