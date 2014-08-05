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
