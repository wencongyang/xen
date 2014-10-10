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

#ifndef BLOCK_REPLICATION_H
#define BLOCK_REPLICATION_H

#include "scheduler.h"
#include <sys/socket.h>
#include <netdb.h>

#define CONTAINER_OF(inner_ptr, outer, member_name)			\
	({								\
		typeof(outer) *container_of_;				\
		container_of_ = (void*)((char*)(inner_ptr) -		\
				offsetof(typeof(outer), member_name));	\
		(void)(&container_of_->member_name ==			\
		       (typeof(inner_ptr))0) /* type check */;		\
		container_of_;						\
	})

#define UNREGISTER_EVENT(id)					\
	do {							\
		if (id >= 0) {					\
			tapdisk_server_unregister_event(id);	\
			id = -1;				\
		}						\
	} while (0)
#define CLOSE_FD(fd)			\
	do {				\
		if (fd >= 0) {		\
			close(fd);	\
			fd = -1;	\
		}			\
	} while (0)

enum {
	ERROR_INTERNAL = -1,
	ERROR_CONNECTION = -2,
	ERROR_IO = -3,
};

typedef struct td_replication_connect td_replication_connect_t;
typedef void td_replication_callback(td_replication_connect_t *r, int rc);

struct td_replication_connect {
	/*
	 * caller must fill these in before calling
	 * td_replication_connect_init()
	 */
	const char *log_prefix;
	td_replication_callback *callback;
	int retry_timeout_s;
	int max_connections;
	/*
	 * The caller uses this fd to read/write after
	 * the connection is established
	 */
	int fd;

	/* private */
	struct sockaddr_in sa;
	int listen_fd;
	event_id_t id;

	int status;
};

/* return -errno if failure happened, otherwise return 0 */
int td_replication_connect_init(td_replication_connect_t *t, const char *name);
/*
 * Return value:
 *   -1: connection is closed or not connected
 *    0: connection is in progress
 *    1: connection is established
 */
int td_replication_connect_status(td_replication_connect_t *t);
void td_replication_connect_kill(td_replication_connect_t *t);

/*
 * Return value:
 *   -2: this caller should be client
 *   -1: error
 *    0: connection is in progress
 */
int td_replication_server_start(td_replication_connect_t *t);
/*
 * Return value:
 *   -2: this caller should be client
 *   -1: error
 *    0: connection is in progress
 */
int td_replication_server_restart(td_replication_connect_t *t);
/*
 * Return value:
 *   -1: error
 *    0: connection is in progress
 */
int td_replication_client_start(td_replication_connect_t *t);

#endif
