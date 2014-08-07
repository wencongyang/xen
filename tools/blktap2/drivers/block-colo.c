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

#include "tapdisk.h"
#include "tapdisk-server.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "block-replication.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* connect retry timeout (seconds) */
#define COLO_CONNRETRY_TIMEOUT  1

/* timeout for reads and writes in second */
#define HEARTBEAT_S 1

/* TAPDISK_DATA_REQUESTS I/O requests + commit flag */
#define MAX_COLO_REQUEST        TAPDISK_DATA_REQUESTS + 1

#undef DPRINTF
#undef EPRINTF
#define DPRINTF(_f, _a...) syslog (LOG_DEBUG, "COLO: " _f, ## _a)
#define EPRINTF(_f, _a...) syslog (LOG_ERR, "COLO: " _f, ## _a)

#define TDCOLO_WRITE "wreq"
#define TDCOLO_COMMIT "creq"
#define TDCOLO_DONE "done"
#define TDCOLO_FAIL "fail"

enum tdcolo_mode {
	mode_invalid = 0,
	mode_unprotected,
	mode_primary,
	mode_backup,

	/*
	 * If we find some internal error in backup mode, we cannot
	 * switch to unprotected mode.
	 */
	mode_failed,
};

enum {
	colo_io,
	colo_commit,
};

typedef struct queued_io {
	int type;
	union {
		td_request_t treq;
		char *buff; /* TDCOLO_COMMIT */
	};
} queued_io_t;

struct queued_io_ring {
	/* waste one slot to distinguish between empty and full */
	queued_io_t qio[MAX_COLO_REQUEST + 1];
	unsigned int prod;
	unsigned int cons;
};

typedef struct colo_control {
	/*
	 * socket file, the user writes "flush" to this socket, and then
	 * we write the result to it.
	 */
	char *path;
	int listen_fd;
	event_id_t listen_id;

	int io_fd;
	event_id_t io_id;
} colo_control_t;

struct tdcolo_state {
	colo_control_t ctl;

	/* async connection */
	td_replication_connect_t t;
	/* replication channel */
	td_async_io_t rio, wio;

	/*
	 * queue I/O requests, and they will be forwarded to backup
	 * asynchronously.
	 */
	struct queued_io_ring qio_ring;

	/* ramdisk data */
	struct ramdisk ramdisk;
	/*
	 * The primary write request is queued in this
	 * hashtable, and will be flushed to ramdisk when
	 * the checkpoint finishes.
	 */
	struct hashtable *h;
	/*
	 * The secondary vm write request is queued in this
	 * hashtable, and will be dropped when the checkpoint
	 * finishes or flushed to ramdisk after failover.
	 */
	struct hashtable *local;

	/* mode methods */
	enum tdcolo_mode mode;
	/* It will be called when switching mode */
	int (*queue_flush)(struct tdcolo_state *c);

	char request[5];
	char header[sizeof(uint32_t) + sizeof(uint64_t)];
	int commit;
	void *buff;
	int bsize;
	int sector_size;
};

struct tap_disk tapdisk_colo;

static void colo_control_respond(colo_control_t *ctl, const char *response);
static int switch_mode(struct tdcolo_state *c, enum tdcolo_mode mode);

/* ======== common functions ======== */
static int check_read_result(td_async_io_t *rio, int realsize,
			     const char *target)
{
	if (realsize < 0) {
		/* internal error */
		EPRINTF("error reading from %s\n", target);
		return ERROR_INTERNAL;
	} else if (realsize < rio->size) {
		/* timeout or I/O error */
		EPRINTF("error reading from %s\n", target);
		return ERROR_IO;
	}

	return 0;
}

static int check_write_result(td_async_io_t *wio, int realsize,
			      const char * target)
{
	if (realsize < 0) {
		/* internal error */
		EPRINTF("error writing to %s\n", target);
		return ERROR_INTERNAL;
	} else if (realsize == 0) {
		/* timeout or I/O error */
		EPRINTF("error writing to %s\n", target);
		return ERROR_IO;
	}

	return 0;
}

/* ======= ring functions ======== */
static inline unsigned int ring_next(unsigned int pos)
{
	if (++pos > MAX_COLO_REQUEST)
		return 0;

	return pos;
}

static inline int ring_isempty(struct queued_io_ring* ring)
{
	return ring->cons == ring->prod;
}

static inline int ring_isfull(struct queued_io_ring* ring)
{
	return ring_next(ring->prod) == ring->cons;
}

static void ring_add_request(struct queued_io_ring *ring,
			     const td_request_t *treq)
{
	/* If ring is full, it means that tapdisk2 has some bug */
	if (ring_isfull(ring)) {
		EPRINTF("OOPS, ring is full\n");
		exit(1);
	}

	ring->qio[ring->prod].type = colo_io;
	ring->qio[ring->prod].treq = *treq;
	ring->prod = ring_next(ring->prod);
}

static void ring_add_commit_flag(struct queued_io_ring *ring)
{
	/* If ring is full, it means that tapdisk2 has some bug */
	if (ring_isfull(ring)) {
		EPRINTF("OOPS, ring is full\n");
		exit(1);
	}

	ring->qio[ring->prod].type = colo_commit;
	ring->qio[ring->prod].buff = TDCOLO_COMMIT;
	ring->prod = ring_next(ring->prod);
}

/* return the first queued I/O request */
static queued_io_t *ring_peek(struct queued_io_ring *ring)
{
	queued_io_t *qio;

	if (ring_isempty(ring))
		return NULL;

	qio = &ring->qio[ring->cons];
	return qio;
}

/* consume the first queued I/O request, and return it */
static queued_io_t *ring_get(struct queued_io_ring *ring)
{
	queued_io_t *qio;

	if (ring_isempty(ring))
		return NULL;

	qio = &ring->qio[ring->cons];
	ring->cons = ring_next(ring->cons);
	return qio;
}

/* ======== primary read/write functions ======== */
static void primary_write_header(td_async_io_t *wio, int realsize, int errnoval);
static void primary_write_data(td_async_io_t *wio, int realsize, int errnoval);
static void primary_forward_done(td_async_io_t *wio, int realsize, int errnoval);
static void primary_read_done(td_async_io_t *rio, int realsize, int errnoval);

/*
 * It is called when we cannot connect to backup, or find I/O error when
 * reading/writing.
 */
static void primary_failed(struct tdcolo_state *c, int rc)
{
	td_replication_connect_kill(&c->t);
	td_async_io_kill(&c->rio);
	td_async_io_kill(&c->wio);
	if (rc == ERROR_INTERNAL)
		EPRINTF("switch to unprotected mode due to internal error");
	if (rc == ERROR_CLOSE)
		DPRINTF("switch to unprotected mode before closing");
	switch_mode(c, mode_unprotected);
}

static void primary_waio(struct tdcolo_state *c, void *buff, size_t size,
			 taio_callback *callback)
{
	td_async_io_t *wio = &c->wio;

	wio->fd = c->t.fd;
	wio->timeout_s = HEARTBEAT_S;
	wio->mode = td_async_write;
	wio->buff = buff;
	wio->size = size;
	wio->callback = callback;

	if (td_async_io_start(wio))
		primary_failed(c, ERROR_INTERNAL);
}

static void primary_raio(struct tdcolo_state *c)
{
	td_async_io_t *rio = &c->rio;

	if (c->t.fd < 0)
		return;

	rio->fd = c->t.fd;
	rio->timeout_s = 0;
	rio->mode = td_async_read;
	rio->buff = c->request;
	rio->size = sizeof(c->request) - 1;
	rio->callback = primary_read_done;

	if (td_async_io_start(rio))
		primary_failed(c, ERROR_INTERNAL);
}

static void primary_handle_queued_io(struct tdcolo_state *c)
{
	struct queued_io_ring *qring = &c->qio_ring;
	unsigned int cons;
	queued_io_t *qio;
	int rc;

	while (!ring_isempty(qring)) {
		qio = ring_peek(qring);
		if (qio->type == colo_commit) {
			primary_waio(c, qio->buff, strlen(qio->buff),
				     primary_forward_done);
			return;
		}

		if (qio->treq.op == TD_OP_WRITE) {
			primary_waio(c, TDCOLO_WRITE, strlen(TDCOLO_WRITE),
				     primary_write_header);
			return;
		}

		td_forward_request(qio->treq);
		ring_get(qring);
	}
}

/* wait for "done" message to commit checkpoint */
static void primary_read_done(td_async_io_t *rio, int realsize, int errnoval)
{
	struct tdcolo_state *c = CONTAINER_OF(rio, *c, rio);
	char *req = c->request;
	int rc;

	rc = check_read_result(rio, realsize, "backup");
	if (rc)
		goto err;

	rc = ERROR_INTERNAL;
	req[4] = '\0';

	if (c->commit != 1) {
		EPRINTF("received unexpected message: %s\n", req);
		goto err;
	}

	c->commit--;

	if (strcmp(req, TDCOLO_DONE)) {
		EPRINTF("received unknown message: %s\n", req);
		goto err;
	}

	/* checkpoint committed, inform msg_fd */
	colo_control_respond(&c->ctl, TDCOLO_DONE);
	primary_raio(c);

	return;
err:
	colo_control_respond(&c->ctl, TDCOLO_FAIL);
	primary_failed(c, rc);
}

static void primary_write_header(td_async_io_t *wio, int realsize, int errnoval)
{
	struct tdcolo_state *c = CONTAINER_OF(wio, *c, wio);
	queued_io_t *qio = ring_peek(&c->qio_ring);
	uint32_t *sectors = (uint32_t *)c->header;
	uint64_t *sector = (uint64_t *)(c->header + sizeof(uint32_t));
	int rc;

	rc = check_write_result(wio, realsize, "backup");
	if (rc) {
		primary_failed(c, rc);
		return;
	}

	*sectors = qio->treq.secs;
	*sector = qio->treq.sec;

	primary_waio(c, c->header, sizeof(c->header), primary_write_data);
}

static void primary_write_data(td_async_io_t *wio, int realsize, int errnoval)
{
	struct tdcolo_state *c = CONTAINER_OF(wio, *c, wio);
	queued_io_t *qio = ring_peek(&c->qio_ring);
	int rc;

	rc = check_write_result(wio, realsize, "backup");
	if (rc) {
		primary_failed(c, rc);
		return;
	}

	primary_waio(c, qio->treq.buf, qio->treq.secs * c->sector_size,
		     primary_forward_done);
}

static void primary_forward_done(td_async_io_t *wio, int realsize, int errnoval)
{
	struct tdcolo_state *c = CONTAINER_OF(wio, *c, wio);
	queued_io_t *qio;
	struct td_request_t *treq;
	int rc;

	rc = check_write_result(wio, realsize, "backup");
	if (rc) {
		primary_failed(c, rc);
		return;
	}

	qio = ring_get(&c->qio_ring);
	if (qio->type == colo_io)
		td_forward_request(qio->treq);
	else
		c->commit--;

	primary_handle_queued_io(c);
}

static void primary_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdcolo_state *c = driver->data;
	struct queued_io_ring *ring = &c->qio_ring;

	if (ring_isempty(ring)) {
		/* just pass read through */
		td_forward_request(treq);
		return;
	}

	ring_add_request(ring, &treq);
	if (td_replication_connect_status(&c->t) != 1)
		return;

	if (!td_async_io_is_running(&c->wio))
		primary_handle_queued_io(c);
}

static void primary_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdcolo_state *c = driver->data;
	struct queued_io_ring *ring = &c->qio_ring;

	ring_add_request(ring, &treq);
	if (td_replication_connect_status(&c->t) != 1)
		return;

	if (!td_async_io_is_running(&c->wio))
		primary_handle_queued_io(c);
}

/* It is called when the user write "flush" to control file. */
static int client_flush(struct tdcolo_state *c)
{
	if (td_replication_connect_status(&c->t) != 1)
		return 0;

	if (c->commit > 0) {
		EPRINTF("the last commit is not finished\n");
		colo_control_respond(&c->ctl, TDCOLO_FAIL);
		primary_failed(c, ERROR_INTERNAL);
		return -1;
	}

	ring_add_commit_flag(&c->qio_ring);
	c->commit = 2;
	if (!td_async_io_is_running(&c->wio))
		primary_handle_queued_io(c);

	return 0;
}

/* It is called when switching the mode from primary to unprotected */
static int primary_flush(struct tdcolo_state *c)
{
	struct queued_io_ring *qring = &c->qio_ring;
	queued_io_t *qio;

	if (ring_isempty(qring))
		return 0;

	while (!ring_isempty(qring)) {
		qio = ring_get(qring);

		if (qio->type == colo_commit) {
			colo_control_respond(&c->ctl, TDCOLO_FAIL);
			c->commit = 0;
			continue;
		}

		td_forward_request(qio->treq);
	}

	return 0;
}

static void colo_client_established(td_replication_connect_t *t, int rc)
{
	struct tdcolo_state *c = CONTAINER_OF(t, *c, t);

	if (rc) {
		primary_failed(c, rc);
		return;
	}

	/* the connect succeeded and handle the queued requests */
	primary_handle_queued_io(c);

	primary_raio(c);
}

static int primary_start(struct tdcolo_state *c)
{
	DPRINTF("activating client mode\n");

	tapdisk_colo.td_queue_read = primary_queue_read;
	tapdisk_colo.td_queue_write = primary_queue_write;
	c->queue_flush = primary_flush;

	c->t.callback = colo_client_established;
	return td_replication_client_start(&c->t);
}

/* ======== backup read/write functions ======== */
static void backup_read_header_done(td_async_io_t *rio, int realsize,
				    int errnoval);
static void backup_read_data_done(td_async_io_t *rio, int realsize,
				  int errnoval);
static void backup_write_done(td_async_io_t *wio, int realsize, int errnoval);

static void backup_failed(struct tdcolo_state *c, int rc)
{
	td_replication_connect_kill(&c->t);
	td_async_io_kill(&c->rio);
	td_async_io_kill(&c->wio);

	if (rc == ERROR_INTERNAL) {
		EPRINTF("switch to failed mode due to internal error");
		switch_mode(c, mode_failed);
		return;
	}

	if (rc == ERROR_CLOSE)
		DPRINTF("switch to unprotected mode before closing");

	switch_mode(c, mode_unprotected);
}

static void backup_raio(struct tdcolo_state *c, void *buff, int size,
			int timeout_s, taio_callback *callback)
{
	td_async_io_t *rio = &c->rio;

	rio->fd = c->t.fd;
	rio->timeout_s = timeout_s;
	rio->mode = td_async_read;
	rio->buff = buff;
	rio->size = size;
	rio->callback = callback;

	if (td_async_io_start(rio)) {
		EPRINTF("cannot start read aio\n");
		backup_failed(c, ERROR_INTERNAL);
	}
}

static void backup_waio(struct tdcolo_state *c)
{
	td_async_io_t *wio = &c->wio;

	wio->fd = c->t.fd;
	wio->timeout_s = HEARTBEAT_S;
	wio->mode = td_async_write;
	wio->buff = TDCOLO_DONE;
	wio->size = strlen(TDCOLO_DONE);
	wio->callback = backup_write_done;

	if (td_async_io_start(wio)) {
		EPRINTF("cannot start write aio\n");
		backup_failed(c, ERROR_INTERNAL);
	}
}

static void backup_read_req_done(td_async_io_t *rio, int realsize,
				 int errnoval)
{
	struct tdcolo_state *c = CONTAINER_OF(rio, *c, rio);
	char *req = c->request;
	int rc;

	rc = check_read_result(rio, realsize, "primary");
	if (rc)
		goto err;

	rc = ERROR_INTERNAL;
	req[4] = '\0';

	if (!strcmp(req, TDCOLO_WRITE)) {
		backup_raio(c, c->header, sizeof(c->header), HEARTBEAT_S,
			    backup_read_header_done);
		return;
	} else if (!strcmp(req, TDCOLO_COMMIT)) {
		ramdisk_destroy_hashtable(c->local);
		c->local = ramdisk_new_hashtable();
		if (!c->local) {
			EPRINTF("error creating local hashtable\n");
			goto err;
		}
		rc = ramdisk_start_flush(&c->ramdisk, &c->h);
		if (rc) {
			EPRINTF("error flushing queued I/O\n");
			goto err;
		}

		backup_waio(c);
	} else {
		EPRINTF("unsupported request: %s\n", req);
		goto err;
	}

	return;

err:
	backup_failed(c, ERROR_INTERNAL);
	return;
}

static void backup_read_header_done(td_async_io_t *rio, int realsize,
				    int errnoval)
{
	struct tdcolo_state *c = CONTAINER_OF(rio, *c, rio);
	uint32_t *sectors = (uint32_t *)c->header;
	int rc;

	rc = check_read_result(rio, realsize, "primary");
	if (rc)
		goto err;

	rc = ERROR_INTERNAL;
	if (*sectors * c->sector_size > c->bsize) {
		EPRINTF("write request is too large: %d/%d\n",
			*sectors * c->sector_size, c->bsize);
		goto err;
	}

	backup_raio(c, c->buff, *sectors * c->sector_size, HEARTBEAT_S,
		    backup_read_data_done);

	return;
err:
	backup_failed(c, rc);
}

static void backup_read_data_done(td_async_io_t *rio, int realsize,
				  int errnoval)
{
	struct tdcolo_state *c = CONTAINER_OF(rio, *c, rio);
	uint32_t *sectors = (uint32_t *)c->header;
	uint64_t *sector = (uint64_t *)(c->header + sizeof(uint32_t));
	int rc;

	rc = check_read_result(rio, realsize, "primary");
	if (rc)
		goto err;

	rc = ramdisk_write_to_hashtable(c->h, *sector, *sectors,
					c->sector_size, c->buff, "COLO");
	if (rc) {
		EPRINTF("cannot write primary data to hashtable\n");
		rc = ERROR_INTERNAL;
		goto err;
	}

	backup_raio(c, c->request, sizeof(c->request) - 1, 0,
		    backup_read_req_done);

	return;
err:
	backup_failed(c, rc);
}

static void backup_write_done(td_async_io_t *wio, int realsize, int errnoval)
{
	struct tdcolo_state *c = CONTAINER_OF(wio, *c, wio);
	int rc;

	rc = check_write_result(wio, realsize, "primary");
	if (rc) {
		backup_failed(c, rc);
		return;
	}

	backup_raio(c, c->request, sizeof(c->request) - 1, 0,
		    backup_read_req_done);
}

static void colo_server_established(td_replication_connect_t *t, int rc)
{
	struct tdcolo_state *c = CONTAINER_OF(t, *c, t);

	if (rc) {
		backup_failed(c, rc);
		return;
	}

	backup_raio(c, c->request, sizeof(c->request) - 1, 0,
		    backup_read_req_done);
}

/* It is called when switching the mode from backup to unprotected */
static int backup_flush(struct tdcolo_state *c)
{
	int rc;

	rc = ramdisk_start_flush(&c->ramdisk, &c->local);
	if (rc)
		EPRINTF("error flushing local queued I/O\n");

	return 0;
}

static void backup_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdcolo_state *c = driver->data;

	if (ramdisk_read_from_hashtable(c->local, treq.sec, treq.secs,
					c->sector_size, treq.buf))
		/* FIXME */
		td_forward_request(treq);
	else
		/* complete the request */
		td_complete_request(treq, 0);
}

static void backup_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdcolo_state *c = driver->data;
	int rc;

	rc = ramdisk_write_to_hashtable(c->local, treq.sec, treq.secs,
					c->sector_size, treq.buf,
					"COLO");
	if (rc)
		td_complete_request(treq, -EBUSY);
	else
		td_complete_request(treq, 0);
}

static int backup_start(struct tdcolo_state *c)
{
	tapdisk_colo.td_queue_read = backup_queue_read;
	tapdisk_colo.td_queue_write = backup_queue_write;
	c->queue_flush = backup_flush;

	c->h = ramdisk_new_hashtable();
	c->local = ramdisk_new_hashtable();
	if (!c->h || !c->local)
		return -1;

	c->bsize = sysconf(_SC_PAGESIZE);
	c->buff = malloc(c->bsize);
	if (!c->buff)
		return -1;

	return 0;
}

/* ======== unprotected read/write functions ======== */
void unprotected_queue_io(td_driver_t *driver, td_request_t treq)
{
	struct tdcolo_state *c = driver->data;

	/* wait for previous ramdisk to flush  before servicing I/O */
	if (ramdisk_writes_inflight(&c->ramdisk)) {
		ramdisk_flush(&c->ramdisk);
		td_complete_request(treq, -EBUSY);
	} else {
		/* here we just pass I/O through */
		td_forward_request(treq);
	}
}

static int unprotected_start(struct tdcolo_state *c)
{
	DPRINTF("failure detected, activating passthrough\n");

	/* install the unprotected read/write handlers */
	tapdisk_colo.td_queue_read = unprotected_queue_io;
	tapdisk_colo.td_queue_write = unprotected_queue_io;
	c->queue_flush = NULL;

	return 0;
}

/* ======== failed read/write functions ======== */
static void failed_queue_io(td_driver_t *driver, td_request_t treq)
{
	td_complete_request(treq, -EIO);
}

static int failed_start(struct tdcolo_state *c)
{
	tapdisk_colo.td_queue_read = failed_queue_io;
	tapdisk_colo.td_queue_write = failed_queue_io;
	c->queue_flush = NULL;

	return 0;
}

/* ======== control ======== */
static void colo_control_accept(event_id_t id, char mode, void *private);
static void colo_control_handle_request(event_id_t id, char mode,
					void *private);
static void colo_control_close(colo_control_t *ctl);

static void colo_control_init(colo_control_t *ctl)
{
	ctl->listen_fd = -1;
	ctl->listen_id = -1;
	ctl->io_fd = -1;
	ctl->io_id = -1;
}

static int colo_create_control_socket(colo_control_t *ctl, const char *name)
{
	int i, l;
	struct sockaddr_un saddr;
	event_id_t id;
	int rc;

	/* first we must ensure that BLKTAP_CTRL_DIR exists */
	if (mkdir(BLKTAP_CTRL_DIR, 0755) && errno != EEXIST) {
		rc = -errno;
		EPRINTF("error creating directory %s: %d\n",
			BLKTAP_CTRL_DIR, errno);
		goto fail;
	}

	/* use the device name to create the control socket path */
	if (asprintf(&ctl->path, BLKTAP_CTRL_DIR "/colo_%s", name) < 0) {
		rc = -errno;
		goto fail;
	}

	/* scrub socket pathname  */
	l = strlen(ctl->path);
	for (i = strlen(BLKTAP_CTRL_DIR) + 1; i < l; i++) {
		if (strchr(":/", ctl->path[i]))
			ctl->path[i] = '_';
	}

	if (unlink(ctl->path) && errno != ENOENT) {
		rc = -errno;
		EPRINTF("failed to unlink %s: %d\n", ctl->path, errno);
		goto fail;
	}

	ctl->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctl->listen_fd == -1) {
		rc = -errno;
		EPRINTF("failed to create control socket: %d\n", errno);
		goto fail;
	}

	memset(&saddr, 0, sizeof(saddr));
	strncpy(saddr.sun_path, ctl->path, sizeof(saddr.sun_path));
	saddr.sun_family = AF_UNIX;

	rc = bind(ctl->listen_fd, (const struct sockaddr *)&saddr,
		  sizeof(saddr));
	if (rc == -1) {
		rc = -errno;
		EPRINTF("failed to bind to %s: %d\n", saddr.sun_path, errno);
		goto fail;
	}

	rc = listen(ctl->listen_fd, 10);
	if (rc == -1) {
		rc = -errno;
		EPRINTF("failed to listen: %d\n", errno);
		goto fail;
	}

	id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					   ctl->listen_fd, 0,
					   colo_control_accept, ctl);
	if (id < 0) {
		EPRINTF("failed to add watch: %d\n", id);
		rc = id;
		goto fail;
	}

	ctl->listen_id = id;
	return 0;

fail:
	colo_control_close(ctl);
	return rc;
}

static void colo_control_accept(event_id_t id, char mode, void *private)
{
	colo_control_t *ctl = private;
	int fd;

	fd = accept(ctl->listen_fd, NULL, NULL);
	if (fd == -1) {
		EPRINTF("failed to accept new control connection: %d\n", errno);
		return;
	}

	if (ctl->io_fd >= 0) {
		EPRINTF("cannot accept two control connections\n");
		close(fd);
		return;
	}

	id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					   fd, 0,
					   colo_control_handle_request,
					   ctl);
	if (id < 0) {
		close(fd);
		EPRINTF("failed to register new control event: %d\n", id);
		return;
	}

	ctl->io_fd = fd;
	ctl->io_id = id;
}

static void colo_control_handle_request(event_id_t id, char mode, void *private)
{
	colo_control_t *ctl = private;
	struct tdcolo_state *c = CONTAINER_OF(ctl, *c, ctl);
	char req[6];
	int rc;

	rc = read(ctl->io_fd, req, sizeof(req) - 1);
	if (!rc) {
		EPRINTF("0-byte read received, close control socket\n");
		goto err;
	}

	if (rc < 0) {
		EPRINTF("error reading from control socket: %d\n", errno);
		goto err;
	}

	req[rc] = '\0';
	if (strncmp(req, "flush", 5)) {
		EPRINTF("unknown command: %s\n", req);
		colo_control_respond(ctl, TDCOLO_FAIL);
		return;
	}

	if (c->mode != mode_primary) {
		EPRINTF("invalid mode: %d\n", c->mode);
		colo_control_respond(ctl, TDCOLO_FAIL);
		return;
	}

	client_flush(c);
	return;

err:
	UNREGISTER_EVENT(ctl->io_id);
	CLOSE_FD(ctl->io_fd);
	return;
}

static void colo_control_respond(colo_control_t *ctl, const char *response)
{
	int rc;

	if (ctl->io_fd < 0)
		return;

	rc = write(ctl->io_fd, response, strlen(response));
	if (rc < 0) {
		EPRINTF("error writing notification: %d\n", errno);
		CLOSE_FD(ctl->io_fd);
	}
}

static void colo_control_close(colo_control_t *ctl)
{
	UNREGISTER_EVENT(ctl->listen_id);
	UNREGISTER_EVENT(ctl->io_id);
	CLOSE_FD(ctl->listen_fd);
	CLOSE_FD(ctl->io_fd);

	if (ctl->path) {
		unlink(ctl->path);
		free(ctl->path);
		ctl->path = NULL;
	}
}

/* ======== interface ======== */
static int tdcolo_close(td_driver_t *driver);

static int switch_mode(struct tdcolo_state *c, enum tdcolo_mode mode)
{
	int rc;

	if (mode == c->mode)
		return 0;

	if (c->queue_flush)
		if ((rc = c->queue_flush(c)) < 0) {
			/* fall back to unprotected mode on error */
			EPRINTF("switch_mode: error flushing queue (old: %d, new: %d)",
				c->mode, mode);
			mode = mode_unprotected;
		}

	if (mode == mode_unprotected)
		rc = unprotected_start(c);
	else if (mode == mode_primary)
		rc = primary_start(c);
	else if (mode == mode_backup)
		rc = backup_start(c);
	else if (mode == mode_failed)
		rc = failed_start(c);
	else {
		EPRINTF("unknown mode requested: %d\n", mode);
		rc = -1;
	}

	if (!rc)
		c->mode = mode;

	return rc;
}

static int tdcolo_open(td_driver_t *driver, td_image_t *image, td_uuid_t uuid)
{
	struct tdcolo_state *c = driver->data;
	td_replication_connect_t *t = &c->t;
	colo_control_t *ctl = &c->ctl;
	ramdisk_t *ramdisk = &c->ramdisk;
	int rc;
	const char *name = image->name;
	td_flag_t flags = image->flags;

	DPRINTF("opening %s\n", name);

	memset(c, 0, sizeof(*c));

	/* init ramdisk */
	ramdisk->log_prefix = "COLO";
	ramdisk->sector_size = driver->info.sector_size;
	ramdisk->image = image;
	ramdisk_init(&c->ramdisk);

	/* init async I/O */
	td_async_io_init(&c->rio);
	td_async_io_init(&c->wio);

	c->sector_size = driver->info.sector_size;

	/* init control socket */
	colo_control_init(ctl);
	rc = colo_create_control_socket(ctl, name);
	if (rc)
		return rc;

	/* init async connection */
	t->log_prefix = "COLO";
	t->retry_timeout_s = COLO_CONNRETRY_TIMEOUT;
	t->max_connections = 1;
	t->callback = colo_server_established;
	rc = td_replication_connect_init(t, name);
	if (rc) {
		colo_control_close(ctl);
		return rc;
	}

	rc = td_replication_server_start(t);
	if (!rc)
		rc = switch_mode(c, mode_backup);
	else if (rc == -2)
		rc = switch_mode(c, mode_primary);

	if (!rc)
		return 0;

	tdcolo_close(driver);
	return -EIO;
}

static int tdcolo_pre_close(td_driver_t *driver)
{
	struct tdcolo_state *c = driver->data;

	if (c->mode != mode_primary)
		return 0;

	if (td_replication_connect_status(&c->t))
		return 0;

	/*
	 * The connection is in progress, and we may queue some
	 * I/O requests.
	 */
	primary_failed(c, ERROR_CLOSE);
	return 0;
}

static int tdcolo_close(td_driver_t *driver)
{
	struct tdcolo_state *c = driver->data;

	DPRINTF("closing\n");
	ramdisk_destroy(&c->ramdisk);
	ramdisk_destroy_hashtable(c->h);
	ramdisk_destroy_hashtable(c->local);
	td_replication_connect_kill(&c->t);
	td_async_io_kill(&c->rio);
	td_async_io_kill(&c->wio);
	colo_control_close(&c->ctl);
	free(c->buff);

	return 0;
}

static int tdcolo_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	/* we shouldn't have a parent... for now */
	return -EINVAL;
}

static int tdcolo_validate_parent(td_driver_t *driver,
				  td_driver_t *pdriver, td_flag_t flags)
{
	return 0;
}

struct tap_disk tapdisk_colo = {
	.disk_type          = "tapdisk_colo",
	.private_data_size  = sizeof(struct tdcolo_state),
	.td_open            = tdcolo_open,
	.td_queue_read      = unprotected_queue_io,
	.td_queue_write     = unprotected_queue_io,
	.td_pre_close       = tdcolo_pre_close,
	.td_close           = tdcolo_close,
	.td_get_parent_id   = tdcolo_get_parent_id,
	.td_validate_parent = tdcolo_validate_parent,
};
