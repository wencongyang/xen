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
	/*
	 * The secondary vm write request is queued in this
	 * hashtable, and will be dropped when the checkpoint
	 * finishes or flushed to ramdisk after failover.
	 */
	struct hashtable *secondary_cache;
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
 * try to read from ramdisk's cache. Return -1 if some sectors are not in
 * ramdisk's cache. Otherwise, return 0.
 */
int ramdisk_read_from_cache(ramdisk_t *ramdisk, uint64_t sector,
			    int nb_sectors, int sector_size,
			    char *buf, int use_primary_cache);

/*
 * cache the write requests, and it will be flushed after a
 * new checkpoint finishes
 */
int ramdisk_cache_write_request(ramdisk_t *ramdisk, uint64_t sector,
				int nb_sectors, size_t sector_size,
				char* buf, const char *log_prefix,
				int use_primary_cache);

/* flush pended write requests to disk */
int ramdisk_flush_pended_requests(ramdisk_t *ramdisk);
/*
 * flush cached write requests to disk. If WAW is detected, the cached
 * write requests will be moved to pended queue. The pended write
 * requests will be auto flushed after all inprogress write requests
 * are flushed to disk. This function don't wait all write requests
 * are flushed to disk.
 */
int ramdisk_start_flush(ramdisk_t *ramdisk, int flush_primary_cache);
/*
 * clear the write requests that are stored in the cache, all write requests
 * will be dropped.
 */
int ramdisk_clear_cache(ramdisk_t *ramdisk, int use_primary_cache);
/*
 * Return true if some write reqeusts are inprogress or pended,
 * otherwise return false
 */
int ramdisk_writes_inflight(ramdisk_t *ramdisk);

/* async I/O, don't support read/write at the same time */
typedef struct td_async_io td_async_io_t;
enum {
	td_async_read,
	td_async_write,
};

/*
 * realsize >= 1 means all data was read/written
 * realsize == 0 means failure happened when reading/writing, and
 * errnoval is valid
 * realsize == -1 means some other internal failure happended, and
 * errnoval is also valid
 * In all cases async_io is killed before calling this callback
 *
 * If we don't read/write any more data in timeout_s seconds, realsize is
 * 0, and errnoval is ETIME
 *
 * If timeout_s is 0, timeout will be disabled.
 *
 * NOTE: realsize is less than taio->size, if we read EOF.
 */
typedef void taio_callback(td_async_io_t *taio, int realsize,
			   int errnoval);

struct td_async_io {
	/* caller must fill these in, and they must all remain valid */
	int fd;
	int timeout_s;
	int mode;
	/*
	 * read: store the data to buff
	 * write: point to the data to be written
	 */
	void *buff;
	int size;
	taio_callback *callback;

	/* private */
	event_id_t timeout_id, io_id;
	int used;
	int running;
};

/* Don't call it when td_async_io is running */
void td_async_io_init(td_async_io_t *taio);
/* return -1 if we find some error. Otherwise, return 0 */
int td_async_io_start(td_async_io_t *taio);
/* return 1 if td_async_io is running, otherwise return 0 */
int td_async_io_is_running(td_async_io_t *taio);
/* The callback will not be called */
void td_async_io_kill(td_async_io_t *taio);

#endif
