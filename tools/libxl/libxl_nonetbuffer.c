/*
 * Copyright (C) 2014
 * Author Shriram Rajagopalan <rshriram@cs.ubc.ca>
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

int libxl__netbuffer_enabled(libxl__gc *gc)
{
    return 0;
}

static void nic_setup(libxl__checkpoint_device *dev)
{
    STATE_AO_GC(dev->cds->ao);

    dev->aodev.rc = ERROR_FAIL;
    dev->aodev.callback(dev->cds->egc, &dev->aodev);
}

static int nic_init(libxl__checkpoint_devices_state *cds)
{
    return 0;
}

static void nic_cleanup(libxl__checkpoint_devices_state *cds)
{
    return;
}

const libxl__checkpoint_device_subkind_ops remus_device_nic = {
    .kind = LIBXL__CHECKPOINT_DEVICE_NIC,
    .init = nic_init,
    .cleanup = nic_cleanup,
    .setup = nic_setup,
};

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
