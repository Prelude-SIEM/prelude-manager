/*****
*
* Copyright (C) 2017-2018 CS-SI. All Rights Reserved.
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

#include "libev/ev.h"


typedef struct {
        ev_io ev;
        ev_timer inactivity_timer;
        ev_timer keepalive_timer;

        ev_tstamp last_activity;
        ev_tstamp last_expect_reply;

        /*
         * RFC 5321, section 4.5.3.1.5:
         *
         * The maximum total length of a reply line including the reply code and
         * the <CRLF> is 512 octets.  More information may be conveyed through
         * multiple-line replies.
         */
        char readbuf[512];
        size_t rlen;

        int fd;

        enum {
                SMTP_IO_STATE_UNKNOWN    = 0,
                SMTP_IO_STATE_CONNECTED  = 1,
        } state;

        prelude_list_t cmd_list;

        const char *server;
        unsigned int keepalive_interval;
        unsigned int inactivity_timeout;
} smtp_conn_t;



int smtp_io_cmd(smtp_conn_t *conn, const char *buf, size_t size, int expected);

int smtp_io_open(smtp_conn_t *conn, const char *server, struct addrinfo *ai);

void smtp_io_destroy(smtp_conn_t *conn);
