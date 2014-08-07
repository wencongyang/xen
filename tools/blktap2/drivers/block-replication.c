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

#include "tapdisk-server.h"
#include "block-replication.h"
#include "tapdisk-interface.h"
#include "hashtable.h"
#include "hashtable_itr.h"
#include "hashtable_utility.h"

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <arpa/inet.h>

#undef DPRINTF
#undef EPRINTF
#define DPRINTF(_f, _a...) syslog (LOG_DEBUG, "%s: " _f, log_prefix, ## _a)
#define EPRINTF(_f, _a...) syslog (LOG_ERR, "%s: " _f, log_prefix, ## _a)

#define RAMDISK_HASHSIZE 128

/* connection status */
enum {
	connection_none,
	connection_in_progress,
	connection_established,
	connection_closed,
};

/* common functions */
/* args should be host:port */
static int get_args(td_replication_connect_t *t, const char* name)
{
	char* host;
	const char* port;
	int gai_status;
	int valid_addr;
	struct addrinfo gai_hints;
	struct addrinfo *servinfo, *servinfo_itr;
	const char *log_prefix = t->log_prefix;

	memset(&gai_hints, 0, sizeof gai_hints);
	gai_hints.ai_family = AF_UNSPEC;
	gai_hints.ai_socktype = SOCK_STREAM;

	port = strchr(name, ':');
	if (!port) {
		EPRINTF("missing host in %s\n", name);
		return -ENOENT;
	}
	if (!(host = strndup(name, port - name))) {
		EPRINTF("unable to allocate host\n");
		return -ENOMEM;
	}
	port++;
	if ((gai_status = getaddrinfo(host, port,
				      &gai_hints, &servinfo)) != 0) {
		EPRINTF("getaddrinfo error: %s\n", gai_strerror(gai_status));
		free(host);
		return -ENOENT;
	}
	free(host);

	/* TODO: do something smarter here */
	valid_addr = 0;
	for (servinfo_itr = servinfo; servinfo_itr != NULL;
	     servinfo_itr = servinfo_itr->ai_next) {
		if (servinfo_itr->ai_family == AF_INET) {
			valid_addr = 1;
			memset(&t->sa, 0, sizeof(t->sa));
			t->sa = *(struct sockaddr_in *)servinfo_itr->ai_addr;
			break;
		}
	}
	freeaddrinfo(servinfo);

	if (!valid_addr)
		return -ENOENT;

	DPRINTF("host: %s, port: %d\n", inet_ntoa(t->sa.sin_addr),
		ntohs(t->sa.sin_port));

	return 0;
}

int td_replication_connect_init(td_replication_connect_t *t, const char *name)
{
	int rc;

	rc = get_args(t, name);
	if (rc)
		return rc;

	t->listen_fd = -1;
	t->id = -1;
	t->status = connection_none;
	return 0;
}

int td_replication_connect_status(td_replication_connect_t *t)
{
	const char *log_prefix = t->log_prefix;

	switch (t->status) {
	case connection_none:
	case connection_closed:
		return -1;
	case connection_in_progress:
		return 0;
	case connection_established:
		return 1;
	default:
		EPRINTF("td_replication_connect is corruptted\n");
		return -2;
	}
}

void td_replication_connect_kill(td_replication_connect_t *t)
{
	if (t->status != connection_in_progress &&
	    t->status != connection_established)
		return;

	UNREGISTER_EVENT(t->id);
	CLOSE_FD(t->fd);
	CLOSE_FD(t->listen_fd);
	t->status = connection_closed;
}

/* server */
static void td_replication_server_accept(event_id_t id, char mode,
					 void *private);

int td_replication_server_start(td_replication_connect_t *t)
{
	int opt;
	int rc = -1;
	event_id_t id;
	int fd;
	const char *log_prefix = t->log_prefix;

	if (t->status == connection_in_progress ||
	    t->status == connection_established)
		return rc;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		EPRINTF("could not create server socket: %d\n", errno);
		return rc;
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET,
		       SO_REUSEADDR, &opt, sizeof(opt)) < 0)
		DPRINTF("Error setting REUSEADDR on %d: %d\n", fd, errno);

	if (bind(fd, (struct sockaddr *)&t->sa, sizeof(t->sa)) < 0) {
		DPRINTF("could not bind server socket %d to %s:%d: %d %s\n",
			fd, inet_ntoa(t->sa.sin_addr),
			ntohs(t->sa.sin_port), errno, strerror(errno));
		if (errno == EADDRNOTAVAIL)
			rc = -2;
		goto err;
	}

	if (listen(fd, t->max_connections)) {
		EPRINTF("could not listen on socket: %d\n", errno);
		goto err;
	}

	/*
	 * The socket is now bound to the address and listening so we
	 * may now register the fd with tapdisk
	 */
	id =  tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					    fd, 0,
					    td_replication_server_accept, t);
	if (id < 0) {
		EPRINTF("error registering server connection event handler: %s",
			strerror(id));
		goto err;
	}
	t->listen_fd = fd;
	t->id = id;
	t->status = connection_in_progress;

	return 0;

err:
	close(fd);
	return rc;
}

static void td_replication_server_accept(event_id_t id, char mode,
					 void *private)
{
	td_replication_connect_t *t = private;
	int fd;
	const char *log_prefix = t->log_prefix;

	/* XXX: add address-based black/white list */
	fd = accept(t->listen_fd, NULL, NULL);
	if (fd < 0) {
		EPRINTF("error accepting connection: %d\n", errno);
		return;
	}

	if (t->status == connection_established) {
		EPRINTF("connection is already established\n");
		close(fd);
		return;
	}

	DPRINTF("server accepted connection\n");
	t->fd = fd;
	t->status = connection_established;
	t->callback(t, 0);
}

int td_replication_server_restart(td_replication_connect_t *t)
{
	switch (t->status) {
	case connection_in_progress:
		return 0;
	case connection_established:
		CLOSE_FD(t->fd);
		t->status = connection_in_progress;
		return 0;
	case connection_none:
	case connection_closed:
		return td_replication_server_start(t);
	default:
		/* not reached */
		return -1;
	}
}

/* client */
static void td_replication_retry_connect_event(event_id_t id, char mode,
					       void *private);
static void td_replication_connect_event(event_id_t id, char mode,
					 void *private);
int td_replication_client_start(td_replication_connect_t *t)
{
	event_id_t id;
	int fd;
	int rc;
	int flags;
	const char *log_prefix = t->log_prefix;

	if (t->status == connection_in_progress ||
	    t->status == connection_established)
		return ERROR_INTERNAL;

	DPRINTF("client connecting to %s:%d...\n",
		inet_ntoa(t->sa.sin_addr), ntohs(t->sa.sin_port));

	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		EPRINTF("could not create client socket: %d\n", errno);
		return ERROR_INTERNAL;
	}

	/* make socket nonblocking */
	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		flags = 0;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		EPRINTF("error setting fd %d to non block mode\n", fd);
		goto err;
	}

	/*
	 * once we have created the socket and populated the address,
	 * we can now start our non-blocking connect. rather than
	 * duplicating code we trigger a timeout on the socket fd,
	 * which calls out nonblocking connect code
	 */
	id = tapdisk_server_register_event(SCHEDULER_POLL_TIMEOUT, fd, 0,
					   td_replication_retry_connect_event,
					   t);
	if(id < 0) {
		EPRINTF("error registering timeout client connection event handler: %s\n",
			strerror(id));
		goto err;
	}

	t->fd = fd;
	t->id = id;
	t->status = connection_in_progress;
	return 0;

err:
	close(fd);
	return ERROR_INTERNAL;
}

static void td_replication_client_failed(td_replication_connect_t *t, int rc)
{
	td_replication_connect_kill(t);
	t->callback(t, rc);
}

static void td_replication_client_done(td_replication_connect_t *t)
{
	UNREGISTER_EVENT(t->id);
	t->status = connection_established;
	t->callback(t, 0);
}

static int td_replication_retry_connect(td_replication_connect_t *t)
{
	event_id_t id;
	const char *log_prefix = t->log_prefix;

	UNREGISTER_EVENT(t->id);

	DPRINTF("connect to server 1 second later");
	id = tapdisk_server_register_event(SCHEDULER_POLL_TIMEOUT,
					   t->fd, t->retry_timeout_s,
					   td_replication_retry_connect_event,
					   t);
	if (id < 0) {
		EPRINTF("error registering timeout client connection event handler: %s\n",
			strerror(id));
		return ERROR_INTERNAL;
	}

	t->id = id;
	return 0;
}

static int td_replication_wait_connect_done(td_replication_connect_t *t)
{
	event_id_t id;
	const char *log_prefix = t->log_prefix;

	UNREGISTER_EVENT(t->id);

	id = tapdisk_server_register_event(SCHEDULER_POLL_WRITE_FD,
					   t->fd, 0,
					   td_replication_connect_event, t);
	if (id < 0) {
		EPRINTF("error registering client connection event handler: %s\n",
			strerror(id));
		return ERROR_INTERNAL;
	}
	t->id = id;

	return 0;
}

/* return 1 if we need to reconnect to backup server */
static int check_connect_errno(int err)
{
	/*
	 * The fd is non-block, so we will not get ETIMEDOUT
	 * after calling connect(). We only can get this errno
	 * by getsockopt().
	 */
	if (err == ECONNREFUSED || err == ENETUNREACH ||
	    err == EAGAIN || err == ECONNABORTED ||
	    err == ETIMEDOUT)
	    return 1;

	return 0;
}

static void td_replication_retry_connect_event(event_id_t id, char mode,
					       void *private)
{
	td_replication_connect_t *t = private;
	int rc, ret;
	const char *log_prefix = t->log_prefix;

	/* do a non-blocking connect */
	ret = connect(t->fd, (struct sockaddr *)&t->sa, sizeof(t->sa));
	if (ret) {
		if (errno == EINPROGRESS) {
			/*
			 * the connect returned EINPROGRESS (nonblocking
			 * connect) we must wait for the fd to be writeable
			 * to determine if the connect worked
			 */
			rc = td_replication_wait_connect_done(t);
			if (rc)
				goto fail;
			return;
		}

		if (check_connect_errno(errno)) {
			rc = td_replication_retry_connect(t);
			if (rc)
				goto fail;
			return;
		}

		/* not recoverable */
		EPRINTF("error connection to server %s\n", strerror(errno));
		rc = ERROR_CONNECTION;
		goto fail;
	}

	/* The connection is established unexpectedly */
	td_replication_client_done(t);

	return;

fail:
	td_replication_client_failed(t, rc);
}

/* callback when nonblocking connect() is finished */
static void td_replication_connect_event(event_id_t id, char mode,
					 void *private)
{
	int socket_errno;
	socklen_t socket_errno_size;
	td_replication_connect_t *t = private;
	int rc;
	const char *log_prefix = t->log_prefix;

	/* check to see if the connect succeeded */
	socket_errno_size = sizeof(socket_errno);
	if (getsockopt(t->fd, SOL_SOCKET, SO_ERROR,
		       &socket_errno, &socket_errno_size)) {
		EPRINTF("error getting socket errno\n");
		return;
	}

	DPRINTF("socket connect returned %d\n", socket_errno);

	if (socket_errno) {
		/* the connect did not succeed */
		if (check_connect_errno(socket_errno)) {
			/*
			 * we can probably assume that the backup is down.
			 * just try again later
			 */
			rc = td_replication_retry_connect(t);
			if (rc)
				goto fail;

			return;
		} else {
			EPRINTF("socket connect returned %d, giving up\n",
				socket_errno);
			rc = ERROR_CONNECTION;
			goto fail;
		}
	}

	td_replication_client_done(t);

	return;

fail:
	td_replication_client_failed(t, rc);
}


/* I/O replication */
static void replicated_write_callback(td_request_t treq, int err)
{
	ramdisk_t *ramdisk = treq.cb_data;
	td_vbd_request_t *vreq = treq.private;
	int i;
	uint64_t start;
	const char *log_prefix = ramdisk->log_prefix;

	/* the write failed for now, lets panic. this is very bad */
	if (err) {
		EPRINTF("ramdisk write failed, disk image is not consistent\n");
		exit(-1);
	}

	/*
	 * The write succeeded. let's pull the vreq off whatever request list
	 * it is on and free() it
	 */
	list_del(&vreq->next);
	free(vreq);

	ramdisk->inflight--;
	start = treq.sec;
	for (i = 0; i < treq.secs; i++) {
		hashtable_remove(ramdisk->inprogress, &start);
		start++;
	}
	free(treq.buf);

	if (!ramdisk->inflight && ramdisk->prev)
		ramdisk_flush(ramdisk);
}

static int
create_write_request(ramdisk_t *ramdisk, td_sector_t sec, int secs, char *buf)
{
	td_request_t treq;
	td_vbd_request_t *vreq;
	td_vbd_t *vbd = ramdisk->image->private;

	treq.op      = TD_OP_WRITE;
	treq.buf     = buf;
	treq.sec     = sec;
	treq.secs    = secs;
	treq.image   = ramdisk->image;
	treq.cb      = replicated_write_callback;
	treq.cb_data = ramdisk;
	treq.id      = 0;
	treq.sidx    = 0;

	vreq         = calloc(1, sizeof(td_vbd_request_t));
	treq.private = vreq;

	if(!vreq)
		return -1;

	vreq->submitting = 1;
	INIT_LIST_HEAD(&vreq->next);
	tapdisk_vbd_move_request(treq.private, &vbd->pending_requests);

	td_forward_request(treq);

	vreq->submitting--;

	return 0;
}

/* http://www.concentric.net/~Ttwang/tech/inthash.htm */
static unsigned int uint64_hash(void *k)
{
	uint64_t key = *(uint64_t*)k;

	key = (~key) + (key << 18);
	key = key ^ (key >> 31);
	key = key * 21;
	key = key ^ (key >> 11);
	key = key + (key << 6);
	key = key ^ (key >> 22);

	return (unsigned int)key;
}

static int rd_hash_equal(void *k1, void *k2)
{
	uint64_t key1, key2;

	key1 = *(uint64_t*)k1;
	key2 = *(uint64_t*)k2;

	return key1 == key2;
}

static int uint64_compare(const void *k1, const void *k2)
{
	uint64_t u1 = *(uint64_t*)k1;
	uint64_t u2 = *(uint64_t*)k2;

	/* u1 - u2 is unsigned */
	return u1 < u2 ? -1 : u1 > u2 ? 1 : 0;
}

/*
 * set psectors to an array of the sector numbers in the hash, returning
 * the number of entries (or -1 on error)
 */
static int ramdisk_get_sectors(struct hashtable *h, uint64_t **psectors,
			       const char *log_prefix)
{
	struct hashtable_itr* itr;
	uint64_t* sectors;
	int count;

	if (!(count = hashtable_count(h)))
		return 0;

	if (!(*psectors = malloc(count * sizeof(uint64_t)))) {
		DPRINTF("ramdisk_get_sectors: error allocating sector map\n");
		return -1;
	}
	sectors = *psectors;

	itr = hashtable_iterator(h);
	count = 0;
	do {
		sectors[count++] = *(uint64_t*)hashtable_iterator_key(itr);
	} while (hashtable_iterator_advance(itr));
	free(itr);

	return count;
}

static int ramdisk_write_hash(struct hashtable *h, uint64_t sector, char *buf,
			      size_t len, const char *log_prefix)
{
	char *v;
	uint64_t *key;

	if ((v = hashtable_search(h, &sector))) {
		memcpy(v, buf, len);
		return 0;
	}

	if (!(v = malloc(len))) {
		DPRINTF("ramdisk_write_hash: malloc failed\n");
		return -1;
	}
	memcpy(v, buf, len);
	if (!(key = malloc(sizeof(*key)))) {
		DPRINTF("ramdisk_write_hash: error allocating key\n");
		free(v);
		return -1;
	}
	*key = sector;
	if (!hashtable_insert(h, key, v)) {
		DPRINTF("ramdisk_write_hash failed on sector %" PRIu64 "\n", sector);
		free(key);
		free(v);
		return -1;
	}

	return 0;
}

/*
 * return -1 for OOM
 * return -2 for merge lookup failure(should not happen)
 * return -3 for WAW race
 * return 0 on success.
 */
static int merge_requests(struct ramdisk *ramdisk, uint64_t start,
			  size_t count, char **mergedbuf)
{
	char* buf;
	char* sector;
	int i;
	uint64_t *key;
	int rc = 0;
	const char *log_prefix = ramdisk->log_prefix;

	if (!(buf = valloc(count * ramdisk->sector_size))) {
		DPRINTF("merge_request: allocation failed\n");
		return -1;
	}

	for (i = 0; i < count; i++) {
		if (!(sector = hashtable_search(ramdisk->prev, &start))) {
			EPRINTF("merge_request: lookup failed on %"PRIu64"\n",
				start);
			free(buf);
			rc = -2;
			goto fail;
		}

		/* Check inprogress requests to avoid waw non-determinism */
		if (hashtable_search(ramdisk->inprogress, &start)) {
			DPRINTF("merge_request: WAR RACE on %"PRIu64"\n",
				start);
			free(buf);
			rc = -3;
			goto fail;
		}

		/*
		 * Insert req into inprogress (brief period of duplication of
		 * hash entries until they are removed from prev. Read tracking
		 * would not be reading wrong entries)
		 */
		if (!(key = malloc(sizeof(*key)))) {
			EPRINTF("%s: error allocating key\n", __FUNCTION__);
			free(buf);
			rc = -1;
			goto fail;
		}
		*key = start;
		if (!hashtable_insert(ramdisk->inprogress, key, NULL)) {
			EPRINTF("%s failed to insert sector %" PRIu64 " into inprogress hash\n",
				__FUNCTION__, start);
			free(key);
			free(buf);
			rc = -1;
			goto fail;
		}

		memcpy(buf + i * ramdisk->sector_size, sector, ramdisk->sector_size);
		start++;
	}

	*mergedbuf = buf;
	return 0;
fail:
	for (start--; i > 0; i--, start--)
		hashtable_remove(ramdisk->inprogress, &start);
	return rc;
}

int ramdisk_flush(ramdisk_t *ramdisk)
{
	uint64_t *sectors;
	char *buf = NULL;
	uint64_t base, batchlen;
	int i, j, count = 0;
	const char *log_prefix = ramdisk->log_prefix;

	/* everything is in flight */
	if (!ramdisk->prev)
		return 0;

	count = ramdisk_get_sectors(ramdisk->prev, &sectors, log_prefix);
	if (count <= 0)
		/* should not happen */
		return count;

	/* Create the inprogress table if empty */
	if (!ramdisk->inprogress)
		ramdisk->inprogress = ramdisk_new_hashtable();

	/* sort and merge sectors to improve disk performance */
	qsort(sectors, count, sizeof(*sectors), uint64_compare);

	for (i = 0; i < count;) {
		base = sectors[i++];
		while (i < count && sectors[i] == sectors[i-1] + 1)
			i++;
		batchlen = sectors[i-1] - base + 1;

		j = merge_requests(ramdisk, base, batchlen, &buf);
		if (j) {
			EPRINTF("ramdisk_flush: merge_requests failed:%s\n",
				j == -1 ? "OOM" :
					(j == -2 ? "missing sector" :
						 "WAW race"));
			if (j == -3)
				continue;
			free(sectors);
			return -1;
		}

		/*
		 * NOTE: create_write_request() creates a treq AND forwards
		 * it down the driver chain
		 *
		 * TODO: handle create_write_request()'s error.
		 */
		create_write_request(ramdisk, base, batchlen, buf);

		ramdisk->inflight++;

		for (j = 0; j < batchlen; j++) {
			buf = hashtable_search(ramdisk->prev, &base);
			free(buf);
			hashtable_remove(ramdisk->prev, &base);
			base++;
		}
	}

	if (!hashtable_count(ramdisk->prev)) {
		/* everything is in flight */
		hashtable_destroy(ramdisk->prev, 0);
		ramdisk->prev = NULL;
	}

	free(sectors);
	return 0;
}

int ramdisk_start_flush(ramdisk_t *ramdisk, struct hashtable **new)
{
	uint64_t *key;
	char *buf;
	int rc = 0;
	int i, j, count, batchlen;
	uint64_t *sectors;
	const char *log_prefix = ramdisk->log_prefix;

	if (!hashtable_count(*new))
		return 0;

	if (ramdisk->prev) {
		/*
		 * a flush request issued while a previous flush is still in
		 * progress will merge with the previous request. If you want
		 * the previous request to be consistent, wait for it to
		 * complete.
		 */
		count = ramdisk_get_sectors(*new, &sectors, log_prefix);
		if (count < 0 )
			return count;

		for (i = 0; i < count; i++) {
			buf = hashtable_search(*new, sectors + i);
			ramdisk_write_hash(ramdisk->prev, sectors[i], buf,
					   ramdisk->sector_size, log_prefix);
		}
		free(sectors);

		hashtable_destroy(*new, 1);
	} else
		ramdisk->prev = *new;

	/*
	 * We create a new hashtable so that new writes can be performed before
	 * the old hashtable is completely drained.
	 */
	*new = ramdisk_new_hashtable();

	return ramdisk_flush(ramdisk);
}

void ramdisk_init(ramdisk_t *ramdisk)
{
	ramdisk->inflight = 0;
	ramdisk->prev = NULL;
	ramdisk->inprogress = NULL;
}

void ramdisk_destroy(ramdisk_t *ramdisk)
{
	const char *log_prefix = ramdisk->log_prefix;

	/*
	 * ramdisk_destroy() is called only when we will close the tapdisk image.
	 * In this case, there are no pending requests in vbd.
	 *
	 * If ramdisk->inflight is not 0, it means that the requests created by
	 * us are still in vbd->pending_requests.
	 */
	if (ramdisk->inflight) {
		/* should not happen */
		EPRINTF("cannot destroy ramdisk\n");
		return;
	}

	if (ramdisk->inprogress) {
		hashtable_destroy(ramdisk->inprogress, 0);
		ramdisk->inprogress = NULL;
	}

	if (ramdisk->prev) {
		hashtable_destroy(ramdisk->prev, 1);
		ramdisk->prev = NULL;
	}
}

int ramdisk_writes_inflight(ramdisk_t *ramdisk)
{
	if (!ramdisk->inflight && !ramdisk->prev)
		return 0;

	return 1;
}

int ramdisk_read(struct ramdisk *ramdisk, uint64_t sector,
		 int nb_sectors, char *buf)
{
	int i;
	char *v;
	uint64_t key;

	for (i = 0; i < nb_sectors; i++) {
		key = sector + i;
		/* check whether it is queued in a previous flush request */
		if (!(ramdisk->prev &&
		    (v = hashtable_search(ramdisk->prev, &key)))) {
			/* check whether it is an ongoing flush */
			if (!(ramdisk->inprogress &&
			    (v = hashtable_search(ramdisk->inprogress, &key))))
				return -1;
		}
		memcpy(buf + i * ramdisk->sector_size, v, ramdisk->sector_size);
	}

	return 0;
}

struct hashtable *ramdisk_new_hashtable(void)
{
	return create_hashtable(RAMDISK_HASHSIZE, uint64_hash, rd_hash_equal);
}

int ramdisk_write_to_hashtable(struct hashtable *h, uint64_t sector,
			       int nb_sectors, size_t sector_size, char* buf,
			       const char *log_prefix)
{
	int i, rc;

	for (i = 0; i < nb_sectors; i++) {
		rc = ramdisk_write_hash(h, sector + i,
					buf + i * sector_size,
					sector_size, log_prefix);
		if (rc)
			return rc;
	}

	return 0;
}

int ramdisk_read_from_hashtable(struct hashtable *h, uint64_t sector,
				int nb_sectors, int sector_size,
				char *buf)
{
	int i;
	uint64_t key;
	char *v;

	for (i = 0; i < nb_sectors; i++) {
		key = sector + i;
		v = hashtable_search(h, &key);
		if (!v)
			return -1;
		memcpy(buf + i * sector_size, v, sector_size);
	}

	return 0;
}

void ramdisk_destroy_hashtable(struct hashtable *h)
{
	if (!h)
		return;

	hashtable_destroy(h, 1);
}

/* async I/O */
static void td_async_io_readable(event_id_t id, char mode, void *private);
static void td_async_io_writeable(event_id_t id, char mode, void *private);
static void td_async_io_timeout(event_id_t id, char mode, void *private);

void td_async_io_init(td_async_io_t *taio)
{
	memset(taio, 0, sizeof(*taio));
	taio->fd = -1;
	taio->timeout_id = -1;
	taio->io_id = -1;
}

int td_async_io_start(td_async_io_t *taio)
{
	event_id_t id;

	if (taio->running)
		return -1;

	if (taio->size <= 0 || taio->fd < 0)
		return -1;

	taio->running = 1;

	if (taio->mode == td_async_read)
		id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
						   taio->fd, 0,
						   td_async_io_readable,
						   taio);
	else if (taio->mode == td_async_write)
		id = tapdisk_server_register_event(SCHEDULER_POLL_WRITE_FD,
						   taio->fd, 0,
						   td_async_io_writeable,
						   taio);
	else
		id = -1;
	if (id < 0)
		goto err;
	taio->io_id = id;

	if (taio->timeout_s) {
		id = tapdisk_server_register_event(SCHEDULER_POLL_TIMEOUT,
						   -1, taio->timeout_s,
						   td_async_io_timeout, taio);
		if (id < 0)
			goto err;
		taio->timeout_id = id;
	}

	taio->used = 0;
	return 0;

err:
	td_async_io_kill(taio);
	return -1;
}

static void td_async_io_callback(td_async_io_t *taio, int realsize,
				 int errnoval)
{
	td_async_io_kill(taio);
	taio->callback(taio, realsize, errnoval);
}

static void td_async_io_update_timeout(td_async_io_t *taio)
{
	event_id_t id;

	if (!taio->timeout_s)
		return;

	tapdisk_server_unregister_event(taio->timeout_id);
	taio->timeout_id = -1;

	id = tapdisk_server_register_event(SCHEDULER_POLL_TIMEOUT,
					   -1, taio->timeout_s,
					   td_async_io_timeout, taio);
	if (id < 0)
		td_async_io_callback(taio, -1, id);
	else
		taio->timeout_id = id;
}

static void td_async_io_readable(event_id_t id, char mode, void *private)
{
	td_async_io_t *taio = private;
	int rc;

	while (1) {
		rc = read(taio->fd, taio->buff + taio->used,
			  taio->size - taio->used);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			td_async_io_callback(taio, 0, errno);
			return;
		}

		if (rc == 0) {
			td_async_io_callback(taio, taio->used, 0);
			return;
		}

		taio->used += rc;
		if (taio->used == taio->size) {
			td_async_io_callback(taio, taio->used, 0);
			return;
		}
	}

	td_async_io_update_timeout(taio);
}

static void td_async_io_writeable(event_id_t id, char mode, void *private)
{
	td_async_io_t *taio = private;
	int rc;

	while (1) {
		rc = write(taio->fd, taio->buff + taio->used,
			   taio->size - taio->used);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			td_async_io_callback(taio, 0, errno);
			return;
		}

		taio->used += rc;
		if (taio->used == taio->size) {
			td_async_io_callback(taio, taio->used, 0);
			return;
		}
	}

	td_async_io_update_timeout(taio);
}

static void td_async_io_timeout(event_id_t id, char mode, void *private)
{
	td_async_io_t *taio = private;

	td_async_io_kill(taio);
	taio->callback(taio, 0, ETIME);
}

int td_async_io_is_running(td_async_io_t *taio)
{
	return taio->running;
}

void td_async_io_kill(td_async_io_t *taio)
{
	if (!taio->running)
		return;

	if (taio->timeout_id >= 0) {
		tapdisk_server_unregister_event(taio->timeout_id);
		taio->timeout_id = -1;
	}

	if (taio->io_id >= 0) {
		tapdisk_server_unregister_event(taio->io_id);
		taio->io_id = -1;
	}

	taio->running = 0;
}
