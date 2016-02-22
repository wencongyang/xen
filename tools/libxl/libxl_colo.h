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

#ifndef LIBXL_COLO_H
#define LIBXL_COLO_H

extern void libxl__colo_restore_setup(libxl__egc *egc,
                                      libxl__colo_restore_state *crs);
extern void libxl__colo_restore_teardown(libxl__egc *egc, void *dcs_void,
                                         int ret, int retval, int errnoval);

extern void libxl__colo_save_setup(libxl__egc *egc,
                                   libxl__colo_save_state *css);
extern void libxl__colo_save_teardown(libxl__egc *egc,
                                      libxl__colo_save_state *css,
                                      int rc);

extern int colo_proxy_setup(libxl__colo_proxy_state *cps);
extern void colo_proxy_teardown(libxl__colo_proxy_state *cps);
extern void colo_proxy_preresume(libxl__colo_proxy_state *cps);
extern void colo_proxy_postresume(libxl__colo_proxy_state *cps);
extern int colo_proxy_checkpoint(libxl__colo_proxy_state *cps,
                                 unsigned int timeout_us);
#endif
