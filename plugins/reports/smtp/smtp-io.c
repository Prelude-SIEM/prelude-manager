/*****
*
* Copyright (C) 2017-2019 CS-SI. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv@gmail.com>
*
* This file is part of the Prelude-Manager program.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libprelude/prelude.h>

#include <assert.h>

#include "smtp-io.h"


typedef struct {
        prelude_list_t list;

        char *cmd;
        size_t cmdlen;

        size_t wlen;
        int expected;
} async_cmd_t;



extern struct ev_loop *manager_worker_loop;



static void async_cmd_destroy(async_cmd_t *cmd)
{
        if ( cmd->cmd )
                free(cmd->cmd);

        prelude_list_del(&cmd->list);
        free(cmd);
}



static int handle_error(smtp_conn_t *conn)
{
        async_cmd_t *cmd;
        prelude_list_t *tmp, *bkp;

        assert(conn->fd > 0);

        ev_io_stop(manager_worker_loop, &conn->ev);
        ev_timer_stop(manager_worker_loop, &conn->keepalive_timer);
        ev_timer_stop(manager_worker_loop, &conn->inactivity_timer);

        conn->rlen = 0;
        close(conn->fd);
        conn->fd = -1;
        conn->state = 0;

        prelude_list_for_each_safe(&conn->cmd_list, tmp, bkp) {
                cmd = prelude_list_entry(tmp, async_cmd_t, list);
                async_cmd_destroy(cmd);
        }

        return -1;
}



static async_cmd_t *get_next_cmd(prelude_list_t *head)
{
        if ( prelude_list_is_empty(head) )
                return NULL;

        return prelude_list_entry(head->next, async_cmd_t, list);
}



static int prepare_next_watchers(smtp_conn_t *conn)
{
        int revents = EV_READ;
        prelude_bool_t waiting = FALSE;
        async_cmd_t *cmd;

        if ( conn->state != SMTP_IO_STATE_CONNECTED ) {
                waiting = TRUE;
                revents = EV_WRITE;
        }

        else {
                cmd = get_next_cmd(&conn->cmd_list);
                if ( cmd ) {
                        if ( cmd->wlen < cmd->cmdlen ) {
                                waiting = TRUE;
                                revents = EV_READ|EV_WRITE;
                        }

                        else if ( cmd->expected )
                                waiting = TRUE;
                }
        }

        if ( revents != conn->ev.events ) {
                ev_io_stop(manager_worker_loop, &conn->ev);
                ev_io_set(&conn->ev, conn->fd, revents);
                ev_io_start(manager_worker_loop, &conn->ev);
        }

        conn->last_expect_reply = (waiting) ? ev_now(manager_worker_loop) : 0;
        return 0;
}



static char *splitbuf(char **in, size_t *insize, const char *delim, size_t delimsize)
{
        char *start, *ptr;

        ptr = memmem(*in, *insize, delim, delimsize);
        if ( ! ptr )
                return NULL;

        start = *in;
        *ptr = 0;
        ptr += delimsize;

        *insize -= ptr - *in;
        *in = ptr;

        return start;
}



static int parse_smtp_reply(const char *in, int *code, const char **msg, prelude_bool_t *multiline)
{
        char *eptr = NULL;

        *code = strtol(in, &eptr, 10);
        if ( eptr == in ) {
                prelude_log(PRELUDE_LOG_ERR, "invalid SMTP server reply '%s'\n", in);
                return -1;
        }

        *multiline = ( *eptr == '-' ) ? TRUE : FALSE;
        *msg = (multiline) ? eptr + 1 : eptr;

        return 0;
}



static int resume_cmd_read(smtp_conn_t *conn, async_cmd_t *cmd)
{
        int code;
        ssize_t ret;
        size_t remaining;
        const char *msg;
        char *ptr, *bkp;
        prelude_bool_t more = TRUE;

        do {
                ret = read(conn->fd, conn->readbuf + conn->rlen, sizeof(conn->readbuf) - conn->rlen);
        } while ( ret < 0 && errno == EINTR );

        if ( ret <= 0 ) {
                if ( ret < 0 )
                        prelude_log(PRELUDE_LOG_ERR, "error reading server reply: %s.\n", prelude_strerror(ret));

                return -1;
        }

        conn->rlen += ret;
        remaining = conn->rlen;

        bkp = conn->readbuf;
        while ( (ptr = splitbuf(&bkp, &remaining, "\r\n", 2)) ) {
                ret = parse_smtp_reply(ptr, &code, &msg, &more);
                if ( ret < 0 )
                        return -1;

                if ( code / 100 != cmd->expected ) {
                        prelude_log(PRELUDE_LOG_ERR, "SMTP transaction failed with server code '%d' (expected %d)\n", code, cmd->expected);
                        return -1;
                }
        }

        if ( bkp != conn->readbuf ) { /* Line(s) have been processed */
                conn->rlen = remaining;
                if ( remaining ) {
                        memmove(conn->readbuf, bkp, remaining);
                        return 0;
                }

                else if ( ! more ) {
                        cmd->expected = -1;
                        return 1;
                }
        }

        /*
         * More data needed.
         */
        if ( conn->rlen == sizeof(conn->readbuf) ) {
                prelude_log(PRELUDE_LOG_ERR, "SMTP server reply exceed maximum length\n");
                return -1;
        }

        return 0;
}



static int resume_cmd_write(smtp_conn_t *conn, async_cmd_t *cmd)
{
        ssize_t ret;

        if ( conn->state != SMTP_IO_STATE_CONNECTED ) {
                int r, val;
                socklen_t len = sizeof(val);

                r = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &val, &len);
                if ( r < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "getsockopt failed: '%s'", strerror(errno));
                        return -1;
                }

                if ( val == 0 ) {
                        conn->state = SMTP_IO_STATE_CONNECTED;
                        prelude_log(PRELUDE_LOG_INFO, "SMTP/async: connection to %s succeeded.\n", conn->server);
                } else {
                        prelude_log(PRELUDE_LOG_WARN, "SMTP/async: could not connect to %s: %s.\n", conn->server, strerror(val));
                        return -1;
                }

                return 0;
        }

        do {
               ret = write(conn->fd, cmd->cmd + cmd->wlen, cmd->cmdlen - cmd->wlen);
        } while ( ret < 0 && errno == EINTR );

        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "SMTP: error writing message: '%s'", strerror(errno));
                return -1;
        }

        prelude_log_debug(4, "SMTP[write(%ld)]: (%.*s)", ret, (int) (cmd->cmdlen - cmd->wlen), cmd->cmd + cmd->wlen);

        cmd->wlen += ret;
        if ( cmd->wlen == cmd->cmdlen ) {
                free(cmd->cmd);
                cmd->cmd = NULL;
                cmd->cmdlen = 0;
        }

        return 0;
}



static void libev_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
        int ret;
        smtp_conn_t *conn = (smtp_conn_t *) w;
        async_cmd_t *cmd = get_next_cmd(&conn->cmd_list);

        if ( ! cmd ) {
                prelude_log(PRELUDE_LOG_ERR, "unexpected SMTP event received\n");
                handle_error(conn);
                return;
        }

        conn->last_activity = ev_now(manager_worker_loop);

        if ( revents & EV_WRITE ) {
                ret = resume_cmd_write(conn, cmd);
                if ( ret < 0 ) {
                        handle_error(conn);
                        return;
                }
        }

        else if ( revents & EV_READ ) {
                ret = resume_cmd_read(conn, cmd);
                if ( ret < 0 ) {
                        handle_error(conn);
                        return;
                }
        }

        /*
         * Done with this command.
         */
        if ( ! cmd->cmd && cmd->expected < 0 )
                async_cmd_destroy(cmd);

        prepare_next_watchers(conn);
}



static void libev_keepalive_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
        smtp_conn_t *conn = w->data;
        ev_tstamp after = conn->last_activity - ev_now(manager_worker_loop) + conn->keepalive_interval;

        if ( after < 0 ) {
                smtp_io_cmd(w->data, "NOOP\r\n", 6, 2);
                after = conn->keepalive_interval;
        }

        ev_timer_set(w, after, 0);
        ev_timer_start(manager_worker_loop, w);
}



static void libev_inactivity_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
        smtp_conn_t *conn = w->data;
        ev_tstamp now = ev_now(manager_worker_loop);
        ev_tstamp after = conn->last_expect_reply - now + conn->inactivity_timeout;

        if ( conn->last_expect_reply && after < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "SMTP server is not responding: closing connection.\n");
                handle_error(conn);
        } else {
                ev_timer_set(w, (conn->last_expect_reply) ? after : conn->inactivity_timeout, 0);
                ev_timer_start(manager_worker_loop, w);
        }
}



int smtp_io_cmd(smtp_conn_t *conn, const char *buf, size_t size, int expected)
{
        async_cmd_t *cmd;
        prelude_bool_t empty = prelude_list_is_empty(&conn->cmd_list);

        assert(buf || expected > 0);

        cmd = calloc(1, sizeof(*cmd));
        if ( ! cmd )
                return -1;

        if ( buf ) {
                cmd->cmd = strndup(buf, size);
                cmd->cmdlen = size;
        }

        cmd->expected = expected;
        prelude_list_add_tail(&conn->cmd_list, &cmd->list);

        if ( empty )
                prepare_next_watchers(conn);

        return 0;
}


static int socket_open(smtp_conn_t *conn, const char *server, struct addrinfo *ai)
{
        int ret;

        conn->server = server;

        conn->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if ( conn->fd < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "SMTP: could not open socket: %s.\n", strerror(errno));
                return -1;
        }

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        ret = fcntl(conn->fd, F_SETFL, O_NONBLOCK);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not set non blocking mode for socket: %s", strerror(errno));
                return ret;
        }
#endif

        ret = connect(conn->fd, ai->ai_addr, ai->ai_addrlen);
        if ( ret < 0 ) {
                if ( errno == EINPROGRESS || errno == EWOULDBLOCK )
                        ev_io_set(&conn->ev, conn->fd, EV_WRITE);
                else {
                        prelude_log(PRELUDE_LOG_WARN, "SMTP: could not connect to %s: %s.\n", server, strerror(errno));
                        close(conn->fd);
                        return -1;
                }
        }

        else if ( ret >= 0 ) {
                conn->state = SMTP_IO_STATE_CONNECTED;
                prelude_log(PRELUDE_LOG_INFO, "SMTP: connection to %s succeeded.\n", server);
        }

        return 0;
}



int smtp_io_open(smtp_conn_t *conn, const char *server, struct addrinfo *ai)
{
        int ret;
        char buf[1024], name[512];

        ev_init(&conn->ev, libev_cb);
        ev_init(&conn->keepalive_timer, libev_keepalive_timer_cb);
        ev_init(&conn->inactivity_timer, libev_inactivity_timer_cb);
        conn->keepalive_timer.data = conn->inactivity_timer.data = conn;

        ret = socket_open(conn, server, ai);
        if ( ret < 0 )
                return ret;

        ret = smtp_io_cmd(conn, NULL, 0, 2);
        if ( ret < 0 )
                return ret;

        ret = gethostname(name, sizeof(name));
        if ( ret < 0 )
                return ret;

        snprintf(buf, sizeof(buf), "HELO %s\r\n", name);

        ret = smtp_io_cmd(conn, buf, strlen(buf), 2);
        if ( ret < 0 )
                return ret;

        conn->last_expect_reply = conn->last_activity = ev_now(manager_worker_loop);
        libev_keepalive_timer_cb(manager_worker_loop, &conn->keepalive_timer, 0);
        libev_inactivity_timer_cb(manager_worker_loop, &conn->inactivity_timer, 0);
        ev_io_start(manager_worker_loop, &conn->ev);

        return 0;
}



void smtp_io_destroy(smtp_conn_t *conn)
{
        if ( conn->fd >= 0 )
                handle_error(conn);
}
