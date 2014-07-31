/* block-remus.c
 *
 * This disk sends all writes to a backup via a network interface before
 * passing them to an underlying device.
 * The backup is a bit more complicated:
 *  1. It applies all incoming writes to a ramdisk.
 *  2. When a checkpoint request arrives, it moves the ramdisk to
 *     a committing state and uses a new ramdisk for subsequent writes.
 *     It also acknowledges the request, to let the sender know it can
 *     release output.
 *  3. The ramdisk flushes its contents to the underlying driver.
 *  4. At failover, the backup waits for the in-flight ramdisk (if any) to
 *     drain before letting the domain be activated.
 *
 * The driver determines whether it is the client or server by attempting
 * to bind to the replication address. If the address is not local,
 * the driver acts as client.
 *
 * The following messages are defined for the replication stream:
 * 1. write request
 *    "wreq"      4
 *    num_sectors 4
 *    sector      8
 *    buffer      (num_sectors * sector_size)
 * 2. submit request (may be used as a barrier
 *    "sreq"      4
 * 3. commit request
 *    "creq"      4
 * After a commit request, the client must wait for a competion message:
 * 4. completion
 *    "done"      4
 */

/* due to architectural choices in tapdisk, block-buffer is forced to
 * reimplement some code which is meant to be private */
#include "tapdisk.h"
#include "tapdisk-server.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "block-replication.h"

#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/stat.h>

/* timeout for reads and writes in ms */
#define HEARTBEAT_MS 1000

/* connect retry timeout (seconds) */
#define REMUS_CONNRETRY_TIMEOUT 1

#define RPRINTF(_f, _a...) syslog (LOG_DEBUG, "remus: " _f, ## _a)

#define MAX_REMUS_REQUEST       TAPDISK_DATA_REQUESTS

enum tdremus_mode {
	mode_invalid = 0,
	mode_unprotected,
	mode_primary,
	mode_backup
};

struct tdremus_req {
	td_request_t treq;
};

struct req_ring {
	/* waste one slot to distinguish between empty and full */
	struct tdremus_req pending_requests[MAX_REMUS_REQUEST + 1];
	unsigned int prod;
	unsigned int cons;
};

/* TODO: This isn't very pretty, but to properly generate our own treqs (needed
 * by the backup) we need to know our td_vbt_t and td_image_t (blktap2
 * internals). As a proper fix, we should consider extending the tapdisk
 * interface with a td_create_request() function, or something similar.
 *
 * For now, we just grab the vbd in the td_open() command, and the td_image_t
 * from the first read request.
 */
td_vbd_t *device_vbd = NULL;
td_image_t *remus_image = NULL;
struct tap_disk tapdisk_remus;

typedef struct poll_fd {
	int        fd;
	event_id_t id;
} poll_fd_t;

struct tdremus_state {
  /* XXX: this is needed so that the server can perform operations on
   * the driver from the stream_fd event handler. fix this. */
	td_driver_t *tdremus_driver;

	/* TODO: we may wish to replace these two FIFOs with a unix socket */
	char*     ctl_path; /* receive flush instruction here */
	poll_fd_t ctl_fd;     /* io_fd slot for control FIFO */
	char*     msg_path; /* output completion message here */
	poll_fd_t msg_fd;

	td_replication_connect_t t;
	poll_fd_t stream_fd;     /* replication channel */

	/*
	 * queue I/O requests, batch-replicate when
	 * the connection is established.
	 */
	struct req_ring queued_io;

	/* ramdisk data */
	struct ramdisk ramdisk;
	/*
	 * The primary write request is queued in this
	 * hashtable, and will be flushed to ramdisk when
	 * the checkpoint finishes.
	 */
	struct hashtable *h;

	/* mode methods */
	enum tdremus_mode mode;
	int (*queue_flush)(td_driver_t *driver);
};

typedef struct tdremus_wire {
	uint32_t op;
	uint64_t id;
	uint64_t sec;
	uint32_t secs;
} tdremus_wire_t;

#define TDREMUS_READ "rreq"
#define TDREMUS_WRITE "wreq"
#define TDREMUS_SUBMIT "sreq"
#define TDREMUS_COMMIT "creq"
#define TDREMUS_DONE "done"
#define TDREMUS_FAIL "fail"

/* primary read/write functions */
static void primary_queue_read(td_driver_t *driver, td_request_t treq);
static void primary_queue_write(td_driver_t *driver, td_request_t treq);

/* backup read/write functions */
static void backup_queue_read(td_driver_t *driver, td_request_t treq);
static void backup_queue_write(td_driver_t *driver, td_request_t treq);

/* unpritected read/write functions */
static void unprotected_queue_read(td_driver_t *driver, td_request_t treq);
static void unprotected_queue_write(td_driver_t *driver, td_request_t treq);

static int tdremus_close(td_driver_t *driver);

static int switch_mode(td_driver_t *driver, enum tdremus_mode mode);
static int ctl_respond(struct tdremus_state *s, const char *response);
static int ctl_register(struct tdremus_state *s);
static void ctl_unregister(struct tdremus_state *s);

/* ring functions */
static inline unsigned int ring_next(unsigned int pos)
{
	if (++pos >= MAX_REMUS_REQUEST + 1)
		return 0;

	return pos;
}

static inline int ring_isempty(struct req_ring* ring)
{
	return ring->cons == ring->prod;
}

static inline int ring_isfull(struct req_ring* ring)
{
	return ring_next(ring->prod) == ring->cons;
}

static void ring_add_request(struct req_ring *ring, const td_request_t *treq)
{
	/* If ring is full, it means that tapdisk2 has some bug */
	if (ring_isfull(ring)) {
		RPRINTF("OOPS, ring is full\n");
		exit(1);
	}

	ring->pending_requests[ring->prod].treq = *treq;
	ring->prod = ring_next(ring->prod);
}

static int ramdisk_start(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	if (s->h) {
		RPRINTF("ramdisk already allocated\n");
		return 0;
	}

	s->ramdisk.sector_size = driver->info.sector_size;
	s->ramdisk.log_prefix = "remus";
	s->ramdisk.image = remus_image;
	ramdisk_init(&s->ramdisk);
	s->h = ramdisk_new_hashtable();

	DPRINTF("Ramdisk started, %zu bytes/sector\n", s->ramdisk.sector_size);

	return 0;
}

/* common client/server functions */
/* mayberead: Time out after a certain interval. */
static int mread(int fd, void* buf, size_t len)
{
	fd_set rfds;
	int rc;
	size_t cur = 0;
	struct timeval tv = {
		.tv_sec = HEARTBEAT_MS / 1000,
		.tv_usec = (HEARTBEAT_MS % 1000) * 1000
	};

	if (!len)
		return 0;

	/* read first. Only select if read is incomplete. */
	rc = read(fd, buf, len);
	while (rc < 0 || cur + rc < len) {
		if (!rc) {
			RPRINTF("end-of-file");
			return -1;
		}
		if (rc < 0 && errno != EAGAIN) {
			RPRINTF("error during read: %s\n", strerror(errno));
			return -1;
		}
		if (rc > 0)
			cur += rc;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		if (!(rc = select(fd + 1, &rfds, NULL, NULL, &tv))) {
			RPRINTF("time out during read\n");
			return -1;
		} else if (rc < 0) {
			RPRINTF("error during select: %d\n", errno);
			return -1;
		}
		rc = read(fd, buf + cur, len - cur);
	}
	/*
	  RPRINTF("read %d bytes\n", cur + rc);
	*/

	return 0;
}

static int mwrite(int fd, void* buf, size_t len)
{
	fd_set wfds;
	size_t cur = 0;
	int rc;
	struct timeval tv = {
		.tv_sec = HEARTBEAT_MS / 1000,
		.tv_usec = (HEARTBEAT_MS % 1000) * 1000
	};

	if (!len)
		return 0;

	/* read first. Only select if read is incomplete. */
	rc = write(fd, buf, len);
	while (rc < 0 || cur + rc < len) {
		if (!rc) {
			RPRINTF("end-of-file");
			return -1;
		}
		if (rc < 0 && errno != EAGAIN) {
			RPRINTF("error during write: %s\n", strerror(errno));
			return -1;
		}
		if (rc > 0)
			cur += rc;

		FD_ZERO(&wfds);
		FD_SET(fd, &wfds);
		if (!(rc = select(fd + 1, NULL, &wfds, NULL, &tv))) {
			RPRINTF("time out during write\n");
			return -1;
		} else if (rc < 0) {
			RPRINTF("error during select: %d\n", errno);
			return -1;
		}
		rc = write(fd, buf + cur, len - cur);
	}
	/*
	  RPRINTF("wrote %d bytes\n", cur + rc);
	*/

	return 0;
	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);
	select(fd + 1, NULL, &wfds, NULL, &tv);
}

/* primary functions */
static void remus_client_event(event_id_t id, char mode, void *private);
static int primary_forward_request(struct tdremus_state *s,
				   const td_request_t *treq);

/*
 * It is called when we cannot connect to backup, or find I/O error when
 * reading/writing.
 */
static void primary_failed(struct tdremus_state *s, int rc)
{
	td_replication_connect_kill(&s->t);
	if (rc == ERROR_INTERNAL)
		RPRINTF("switch to unprotected mode due to internal error");
	if (rc == ERROR_CLOSE)
		RPRINTF("switch to unprotected mode before closing");
	UNREGISTER_EVENT(s->stream_fd.id);
	switch_mode(s->tdremus_driver, mode_unprotected);
}

static int remus_handle_queued_io(struct tdremus_state *s)
{
	struct req_ring *queued_io = &s->queued_io;
	unsigned int cons;
	td_request_t *treq;
	int rc;

	while (!ring_isempty(queued_io)) {
		cons = queued_io->cons;
		treq = &queued_io->pending_requests[cons].treq;

		if (treq->op == TD_OP_WRITE) {
			rc = primary_forward_request(s, treq);
			if (rc)
				return rc;
		}

		td_forward_request(*treq);
		queued_io->cons = ring_next(cons);
	}

	return 0;
}

static void remus_client_established(td_replication_connect_t *t, int rc)
{
	struct tdremus_state *s = CONTAINER_OF(t, *s, t);
	event_id_t id;

	if (rc) {
		primary_failed(s, rc);
		return;
	}

	/* the connect succeeded */
	id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD, t->fd,
					   0, remus_client_event, s);
	if(id < 0) {
		RPRINTF("error registering client event handler: %s\n",
			strerror(id));
		primary_failed(s, ERROR_INTERNAL);
		return;
	}

	s->stream_fd.fd = t->fd;
	s->stream_fd.id = id;

	/* handle the queued requests */
	rc = remus_handle_queued_io(s);
	if (rc)
		primary_failed(s, rc);
}

/*
 * we install this event handler on the primary once we have
 * connected to the backup.
 */
/* wait for "done" message to commit checkpoint */
static void remus_client_event(event_id_t id, char mode, void *private)
{
	struct tdremus_state *s = (struct tdremus_state *)private;
	char req[5];
	int rc;

	if (mread(s->stream_fd.fd, req, sizeof(req) - 1) < 0) {
		/*
		 * replication stream closed or otherwise broken
		 * (timeout, reset, &c)
		 */
		RPRINTF("error reading from backup\n");
		primary_failed(s, ERROR_IO);
		return;
	}

	req[4] = '\0';

	if (!strcmp(req, TDREMUS_DONE))
		/* checkpoint committed, inform msg_fd */
		ctl_respond(s, TDREMUS_DONE);
	else {
		RPRINTF("received unknown message: %s\n", req);
		primary_failed(s, ERROR_IO);
	}

	return;
}

static void primary_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	struct req_ring *ring = &s->queued_io;

	if (ring_isempty(ring)) {
		/* just pass read through */
		td_forward_request(treq);
		return;
	}

	ring_add_request(ring, &treq);
}

static int primary_forward_request(struct tdremus_state *s,
				   const td_request_t *treq)
{
	char header[sizeof(uint32_t) + sizeof(uint64_t)];
	uint32_t *sectors = (uint32_t *)header;
	uint64_t *sector = (uint64_t *)(header + sizeof(uint32_t));
	td_driver_t *driver = s->tdremus_driver;

	*sectors = treq->secs;
	*sector = treq->sec;

	if (mwrite(s->stream_fd.fd, TDREMUS_WRITE, strlen(TDREMUS_WRITE)) < 0)
		return ERROR_IO;

	if (mwrite(s->stream_fd.fd, header, sizeof(header)) < 0)
		return ERROR_IO;

	if (mwrite(s->stream_fd.fd, treq->buf,
	    treq->secs * driver->info.sector_size) < 0)
		return ERROR_IO;

	return 0;
}

/* TODO:
 * The primary uses mwrite() to write the contents of a write request to the
 * backup. This effectively blocks until all data has been copied into a system
 * buffer or a timeout has occured. We may wish to instead use tapdisk's
 * nonblocking i/o interface, tapdisk_server_register_event(), to set timeouts
 * and write data in an asynchronous fashion.
 */
static void primary_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int rc, ret;

	// RPRINTF("write: stream_fd.fd: %d\n", s->stream_fd.fd);

	ret = td_replication_connect_status(&s->t);
	if(ret == -1) {
		RPRINTF("connecting to backup...\n");
		s->t.callback = remus_client_established;
		rc = td_replication_client_start(&s->t);
		if (rc)
			goto fail;
	}

	/* The connection is not established, just queue the request */
	if (ret != 1) {
		ring_add_request(&s->queued_io, &treq);
		return;
	}

	/* The connection is established */
	rc = primary_forward_request(s, &treq);
	if (rc)
		goto fail;

	td_forward_request(treq);

	return;

fail:
	/* switch to unprotected mode and forward the request */
	RPRINTF("write request replication failed, switching to unprotected mode");
	primary_failed(s, rc);
	td_forward_request(treq);
}

/* It is called when the user write "flush" to control file. */
static int client_flush(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	// RPRINTF("committing output\n");

	if (s->stream_fd.fd == -1)
		/* connection not yet established, nothing to flush */
		return 0;

	if (mwrite(s->stream_fd.fd, TDREMUS_COMMIT,
	    strlen(TDREMUS_COMMIT)) < 0) {
		RPRINTF("error flushing output");
		primary_failed(s, ERROR_IO);
		return -1;
	}

	return 0;
}

/* It is called when switching the mode from primary to unprotected */
static int primary_flush(td_driver_t *driver)
{
	struct tdremus_state *s = driver->data;
	struct req_ring *ring = &s->queued_io;
	unsigned int cons;

	if (ring_isempty(ring))
		return 0;

	while (!ring_isempty(ring)) {
		cons = ring->cons;
		ring->cons = ring_next(cons);

		td_forward_request(ring->pending_requests[cons].treq);
	}

	return 0;
}

static int primary_start(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	RPRINTF("activating client mode\n");

	tapdisk_remus.td_queue_read = primary_queue_read;
	tapdisk_remus.td_queue_write = primary_queue_write;
	s->queue_flush = primary_flush;

	s->stream_fd.fd = -1;
	s->stream_fd.id = -1;

	return 0;
}

/* backup functions */
static void remus_server_event(event_id_t id, char mode, void *private);

/* It is called when we find some I/O error */
static void backup_failed(struct tdremus_state *s, int rc)
{
	td_replication_connect_kill(&s->t);
	/* We will switch to unprotected mode in backup_queue_write() */
}

/* returns the socket that receives write requests */
static void remus_server_established(td_replication_connect_t *t, int rc)
{
	struct tdremus_state *s = CONTAINER_OF(t, *s, t);
	event_id_t id;

	/* rc is always 0 */

	/* add tapdisk event for replication stream */
	id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD, t->fd, 0,
					   remus_server_event, s);

	if (id < 0) {
		RPRINTF("error registering connection event handler: %s\n",
			strerror(errno));
		td_replication_server_restart(t);
		return;
	}

	/* store replication file descriptor */
	s->stream_fd.fd = t->fd;
	s->stream_fd.id = id;
}

/* wait for latest checkpoint to be applied */
static inline int server_writes_inflight(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	return ramdisk_writes_inflight(&s->ramdisk);
}

/* Due to block device prefetching this code may be called on the server side
 * during normal replication. In this case we must return EBUSY, otherwise the
 * domain may be started with stale data.
 */
void backup_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int i;
	
	/* check if this read is queued in any currently ongoing flush */
	if (ramdisk_read(&s->ramdisk, treq.sec, treq.secs, treq.buf)) {
		/* TODO: Add to pending read hash */
		td_forward_request(treq);
	} else {
		/* complete the request */
		td_complete_request(treq, 0);
	}
}

/* see above */
void backup_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	/* on a server write, we know the domain has failed over. we must change our
	 * state to unprotected and then have the unprotected queue_write function
	 * handle the write
	 */

	switch_mode(driver, mode_unprotected);
	/* TODO: call the appropriate write function rather than return EBUSY */
	td_complete_request(treq, -EBUSY);
}

static int server_flush(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	/* Try to flush any remaining requests */
	return ramdisk_flush(&s->ramdisk);
}

static int backup_start(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	if (ramdisk_start(driver) < 0)
		return -1;

	tapdisk_remus.td_queue_read = backup_queue_read;
	tapdisk_remus.td_queue_write = backup_queue_write;
	s->queue_flush = server_flush;
	return 0;
}

static void server_do_wreq(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	static tdremus_wire_t twreq;
	char buf[4096];
	int len, rc = ERROR_IO;

	char header[sizeof(uint32_t) + sizeof(uint64_t)];
	uint32_t *sectors = (uint32_t *) header;
	uint64_t *sector =  (uint64_t *) &header[sizeof(uint32_t)];

	// RPRINTF("received write request\n");

	if (mread(s->stream_fd.fd, header, sizeof(header)) < 0)
		goto err;

	len = *sectors * driver->info.sector_size;

	//RPRINTF("writing %d sectors (%d bytes) starting at %" PRIu64 "\n", *sectors, len,
	// *sector);

	if (len > sizeof(buf)) {
		/* freak out! How to handle the remaining data from primary */
		RPRINTF("write request too large: %d/%u\n",
			len, (unsigned)sizeof(buf));
		goto err;
	}

	if (mread(s->stream_fd.fd, buf, len) < 0)
		goto err;

	if (ramdisk_write_to_hashtable(s->h, *sector, *sectors,
				       driver->info.sector_size, buf,
				       "remus") < 0) {
		rc = ERROR_INTERNAL;
		goto err;
	}

	return;

 err:
	/* should start failover */
	RPRINTF("backup write request error\n");
	backup_failed(s, rc);
}

static void server_do_sreq(td_driver_t *driver)
{
	/*
	  RPRINTF("submit request received\n");
  */

	return;
}

/* at this point, the server can start applying the most recent
 * ramdisk. */
static void server_do_creq(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	// RPRINTF("committing buffer\n");

	ramdisk_start_flush(&s->ramdisk, &s->h);

	/* XXX this message should not be sent until flush completes! */
	if (write(s->stream_fd.fd, TDREMUS_DONE, strlen(TDREMUS_DONE)) != 4)
		backup_failed(s, ERROR_IO);
}


/* called when data is pending in s->rfd */
static void remus_server_event(event_id_t id, char mode, void *private)
{
	struct tdremus_state *s = (struct tdremus_state *)private;
	td_driver_t *driver = s->tdremus_driver;
	char req[5];

	// RPRINTF("replication data waiting\n");

	/* TODO: add a get_connection_by_event_id() function.
	 * for now we can assume that the fd is s->stream_fd */

	if (mread(s->stream_fd.fd, req, sizeof(req) - 1) < 0) {
		RPRINTF("error reading server event, activating backup\n");
		switch_mode(driver, mode_unprotected);
		return;
	}

	req[4] = '\0';

	if (!strcmp(req, TDREMUS_WRITE))
		server_do_wreq(driver);
	else if (!strcmp(req, TDREMUS_SUBMIT))
		server_do_sreq(driver);
	else if (!strcmp(req, TDREMUS_COMMIT))
		server_do_creq(driver);
	else
		RPRINTF("unknown request received: %s\n", req);

	return;

}

/* unprotected */

void unprotected_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	/* wait for previous ramdisk to flush  before servicing reads */
	if (server_writes_inflight(driver)) {
		ramdisk_flush(&s->ramdisk);

		td_complete_request(treq, -EBUSY);
	}
	else {
		/* here we just pass reads through */
		td_forward_request(treq);
	}
}

/* For a recoverable remus solution we need to log unprotected writes here */
void unprotected_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	/* wait for previous ramdisk to flush */
	if (server_writes_inflight(driver)) {
		RPRINTF("queue_write: waiting for queue to drain");
		ramdisk_flush(&s->ramdisk);
		td_complete_request(treq, -EBUSY);
	}
	else {
		// RPRINTF("servicing write request on backup\n");
		/* NOTE: DRBD style bitmap tracking could go here */
		td_forward_request(treq);
	}
}

static int unprotected_start(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	RPRINTF("failure detected, activating passthrough\n");


	/* install the unprotected read/write handlers */
	tapdisk_remus.td_queue_read = unprotected_queue_read;
	tapdisk_remus.td_queue_write = unprotected_queue_write;

	return 0;
}


/* control */
static int switch_mode(td_driver_t *driver, enum tdremus_mode mode)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int rc;

	if (mode == s->mode)
		return 0;

	if (s->queue_flush)
		if ((rc = s->queue_flush(driver)) < 0) {
			// fall back to unprotected mode on error
			RPRINTF("switch_mode: error flushing queue (old: %d, new: %d)", s->mode, mode);
			mode = mode_unprotected;
		}

	if (mode == mode_unprotected)
		rc = unprotected_start(driver);
	else if (mode == mode_primary)
		rc = primary_start(driver);
	else if (mode == mode_backup)
		rc = backup_start(driver);
	else {
		RPRINTF("unknown mode requested: %d\n", mode);
		rc = -1;
	}

	if (!rc)
		s->mode = mode;

	return rc;
}

static void ctl_reopen(struct tdremus_state *s)
{
	ctl_unregister(s);
	CLOSE_FD(s->ctl_fd.fd);
	RPRINTF("FIFO closed\n");

	if ((s->ctl_fd.fd = open(s->ctl_path, O_RDWR)) < 0) {
		RPRINTF("error reopening FIFO: %d\n", errno);
		return;
	}
	ctl_register(s);
}

static void ctl_request(event_id_t id, char mode, void *private)
{
	struct tdremus_state *s = (struct tdremus_state *)private;
	td_driver_t *driver = s->tdremus_driver;
	char msg[80];
	int rc;

	// RPRINTF("data waiting on control fifo\n");

	if (!(rc = read(s->ctl_fd.fd, msg, sizeof(msg) - 1 /* append nul */))) {
		RPRINTF("0-byte read received, reopening FIFO\n");
		return;
	}

	if (rc < 0) {
		RPRINTF("error reading from FIFO: %d\n", errno);
		return;
	}

	msg[rc] = '\0';
	if (strncmp(msg, "flush", 5)) {
		RPRINTF("unknown command: %s\n", msg);
		ctl_respond(s, TDREMUS_FAIL);
		return;
	}

	if (s->mode != mode_primary) {
		RPRINTF("We are not in primary mode\n");
		ctl_respond(s, TDREMUS_FAIL);
		return;
	}

	rc = client_flush(driver);
	if (rc) {
		RPRINTF("error passing flush request to backup");
		ctl_respond(s, TDREMUS_FAIL);
	}
}

static int ctl_respond(struct tdremus_state *s, const char *response)
{
	int rc;

	if ((rc = write(s->msg_fd.fd, response, strlen(response))) < 0) {
		RPRINTF("error writing notification: %d\n", errno);
		close(s->msg_fd.fd);
		if ((s->msg_fd.fd = open(s->msg_path, O_RDWR)) < 0)
			RPRINTF("error reopening FIFO: %d\n", errno);
	}

	return rc;
}

/* must be called after the underlying driver has been initialized */
static int ctl_open(td_driver_t *driver, const char* name)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int i, l;

	/* first we must ensure that BLKTAP_CTRL_DIR exists */
	if (mkdir(BLKTAP_CTRL_DIR, 0755) && errno != EEXIST)
	{
		DPRINTF("error creating directory %s: %d\n", BLKTAP_CTRL_DIR, errno);
		return -1;
	}

	/* use the device name to create the control fifo path */
	if (asprintf(&s->ctl_path, BLKTAP_CTRL_DIR "/remus_%s", name) < 0)
		return -1;
	/* scrub fifo pathname  */
	for (i = strlen(BLKTAP_CTRL_DIR) + 1, l = strlen(s->ctl_path); i < l; i++) {
		if (strchr(":/", s->ctl_path[i]))
			s->ctl_path[i] = '_';
	}
	if (asprintf(&s->msg_path, "%s.msg", s->ctl_path) < 0)
		goto err_setmsgfifo;

	if (mkfifo(s->ctl_path, S_IRWXU|S_IRWXG|S_IRWXO) && errno != EEXIST) {
		RPRINTF("error creating control FIFO %s: %d\n", s->ctl_path, errno);
		goto err_mkctlfifo;
	}

	if (mkfifo(s->msg_path, S_IRWXU|S_IRWXG|S_IRWXO) && errno != EEXIST) {
		RPRINTF("error creating message FIFO %s: %d\n", s->msg_path, errno);
		goto err_mkmsgfifo;
	}

	/* RDWR so that fd doesn't block select when no writer is present */
	if ((s->ctl_fd.fd = open(s->ctl_path, O_RDWR)) < 0) {
		RPRINTF("error opening control FIFO %s: %d\n", s->ctl_path, errno);
		goto err_openctlfifo;
	}

	if ((s->msg_fd.fd = open(s->msg_path, O_RDWR)) < 0) {
		RPRINTF("error opening message FIFO %s: %d\n", s->msg_path, errno);
		goto err_openmsgfifo;
	}

	RPRINTF("control FIFO %s\n", s->ctl_path);
	RPRINTF("message FIFO %s\n", s->msg_path);

	return 0;

err_openmsgfifo:
	close(s->ctl_fd.fd);
	s->ctl_fd.fd = -1;
err_openctlfifo:
	unlink(s->ctl_path);
err_mkmsgfifo:
	unlink(s->msg_path);
err_mkctlfifo:
	free(s->msg_path);
	s->msg_path = NULL;
err_setmsgfifo:
	free(s->ctl_path);
	s->ctl_path = NULL;
	return -1;
}

static void ctl_close(struct tdremus_state *s)
{
	if(s->ctl_fd.fd) {
		close(s->ctl_fd.fd);
		s->ctl_fd.fd = -1;
	}

	if (s->ctl_path) {
		unlink(s->ctl_path);
		free(s->ctl_path);
		s->ctl_path = NULL;
	}

	if (s->msg_path) {
		unlink(s->msg_path);
		free(s->msg_path);
		s->msg_path = NULL;
	}

	if (s->msg_fd.fd) {
		close(s->msg_fd.fd);
		s->msg_fd.fd = -1;
	}
}

static int ctl_register(struct tdremus_state *s)
{
	RPRINTF("registering ctl fifo\n");

	/* register ctl fd */
	s->ctl_fd.id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD, s->ctl_fd.fd, 0, ctl_request, s);

	if (s->ctl_fd.id < 0) {
		RPRINTF("error registering ctrl FIFO %s: %d\n",
			s->ctl_path, s->ctl_fd.id);
		return -1;
	}

	return 0;
}

static void ctl_unregister(struct tdremus_state *s)
{
	RPRINTF("unregistering ctl fifo\n");

	UNREGISTER_EVENT(s->ctl_fd.id);
}

/* interface */

static int tdremus_open(td_driver_t *driver, td_image_t *image, td_uuid_t uuid)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	td_replication_connect_t *t = &s->t;
	int rc;
	const char *name = image->name;
	td_flag_t flags = image->flags;

	RPRINTF("opening %s\n", name);

	device_vbd = tapdisk_server_get_vbd(uuid);
	remus_image = image;

	memset(s, 0, sizeof(*s));
	s->stream_fd.fd = -1;
	s->ctl_fd.fd = -1;
	s->msg_fd.fd = -1;

	/* TODO: this is only needed so that the server can send writes down
	 * the driver stack from the stream_fd event handler */
	s->tdremus_driver = driver;

	t->log_prefix = "remus";
	t->retry_timeout_s = REMUS_CONNRETRY_TIMEOUT;
	t->max_connections = 10;
	t->callback = remus_server_established;
	/* parse name to get info etc */
	if ((rc = td_replication_connect_init(t, name)))
		return rc;

	if ((rc = ctl_open(driver, name))) {
		RPRINTF("error setting up control channel\n");
		return rc;
	}

	if ((rc = ctl_register(s))) {
		RPRINTF("error registering control channel\n");
		ctl_close(s);
		return rc;
	}

	if (!(rc = td_replication_server_start(t)))
		rc = switch_mode(driver, mode_backup);
	else if (rc == -2)
		rc = switch_mode(driver, mode_primary);

	if (!rc)
		return 0;

	tdremus_close(driver);
	return -EIO;
}

static int tdremus_pre_close(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	if (s->mode != mode_primary)
		return 0;

	primary_failed(s, ERROR_CLOSE);
	return 0;
}

static int tdremus_close(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	RPRINTF("closing\n");
	ramdisk_destroy(&s->ramdisk);
	ramdisk_destroy_hashtable(s->h);
	td_replication_connect_kill(&s->t);
	ctl_unregister(s);
	ctl_close(s);

	return 0;
}

static int tdremus_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	/* we shouldn't have a parent... for now */
	return -EINVAL;
}

static int tdremus_validate_parent(td_driver_t *driver,
				   td_driver_t *pdriver, td_flag_t flags)
{
	return 0;
}

struct tap_disk tapdisk_remus = {
	.disk_type          = "tapdisk_remus",
	.private_data_size  = sizeof(struct tdremus_state),
	.td_open            = tdremus_open,
	.td_queue_read      = unprotected_queue_read,
	.td_queue_write     = unprotected_queue_write,
	.td_pre_close       = tdremus_pre_close,
	.td_close           = tdremus_close,
	.td_get_parent_id   = tdremus_get_parent_id,
	.td_validate_parent = tdremus_validate_parent,
	.td_debug           = NULL,
};
