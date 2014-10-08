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
	ERROR_CLOSE = -4,
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

/* I/O replication */
typedef struct ramdisk ramdisk_t;
struct ramdisk {
	size_t sector_size;
	const char *log_prefix;
	td_image_t *image;

	/* private */
	/* count of outstanding requests to the base driver */
	size_t inflight;
	/* prev holds the requests to be flushed, while inprogress holds
	 * requests being flushed. When requests complete, they are removed
	 * from inprogress.
	 * Whenever a new flush is merged with ongoing flush (i.e, prev),
	 * we have to make sure that none of the new requests overlap with
	 * ones in "inprogress". If it does, keep it back in prev and dont issue
	 * IO until the current one finishes. If we allow this IO to proceed,
	 * we might end up with two "overlapping" requests in the disk's queue and
	 * the disk may not offer any guarantee on which one is written first.
	 * IOW, make sure we dont create a write-after-write time ordering constraint.
	 */
	struct hashtable *prev;
	struct hashtable *inprogress;
	/*
	 * The primary write request is queued in this
	 * hashtable, and will be flushed to ramdisk when
	 * the checkpoint finishes.
	 */
	struct hashtable *primary_cache;
};

int ramdisk_init(ramdisk_t *ramdisk);
void ramdisk_destroy(ramdisk_t *ramdisk);

/*
 * try to read from ramdisk. Return -1 if some sectors are not in
 * ramdisk. Otherwise, return 0.
 */
int ramdisk_read(ramdisk_t *ramdisk, uint64_t sector,
		 int nb_sectors, char *buf);

/*
 * cache the write requests, and it will be flushed after a
 * new checkpoint finishes
 */
int ramdisk_cache_write_request(ramdisk_t *ramdisk, uint64_t sector,
				int nb_sectors, size_t sector_size,
				char* buf, const char *log_prefix);

/* flush pended write requests to disk */
int ramdisk_flush_pended_requests(ramdisk_t *ramdisk);
/*
 * flush cached write requests to disk. If WAW is detected, the cached
 * write requests will be moved to pended queue. The pended write
 * requests will be auto flushed after all inprogress write requests
 * are flushed to disk. This function don't wait all write requests
 * are flushed to disk.
 */
int ramdisk_start_flush(ramdisk_t *ramdisk);
/*
 * Return true if some write reqeusts are inprogress or pended,
 * otherwise return false
 */
int ramdisk_writes_inflight(ramdisk_t *ramdisk);

#endif
