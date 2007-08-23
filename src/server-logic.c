
/*****
*
* Copyright (C) 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
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
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "libmissing.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <libprelude/prelude-inttypes.h>
#include <libprelude/prelude-list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>

#include "server-logic.h"

#define POLL_SLEEP_MS           250


#define LOGIC_FLAGS_WRITE    0x01
#define LOGIC_FLAGS_READ     0x02
#define LOGIC_FLAGS_CLOSING  0x04


#define EMPTY_THREAD_TTL          60
#define DEFAULT_MIN_THREAD         0
#define DEFAULT_MAX_CONNECTION     0


/*
 * If modifying this value beside 256, take care
 * about the size of the sig_atomic_t index, which could be
 * only 8 bits long on some architecture.
 */
#define DEFAULT_MAX_FD_BY_THREAD 100

#define dprint(args...) prelude_log_debug(10, args)


struct server_logic_client {
        SERVER_LOGIC_CLIENT_OBJECT;
};



typedef struct server_fd_set {
        prelude_list_t list;

        /*
         * Thread handling this set of file descriptor.
         */
        pthread_t thread;


        /*
         * Array containing client / file descriptor polling related data.
         */
        struct pollfd *pfd;
        server_logic_client_t **client;
        prelude_bool_t rescan_pfd;

        /*
         * Index used to address free client data / pfd.
         */
        volatile sig_atomic_t used_index;

        server_logic_t *parent;

        /*
         * Used on startup
         */
        pthread_cond_t startup_cond;
        pthread_mutex_t startup_mutex;

        time_t last_time_used;

} server_fd_set_t;



struct server_logic {
        void *sdata;

        server_logic_read_t *read;
        server_logic_write_t *write;
        server_logic_close_t *close;

        /*
         * Maximum number of connection for this server.
         */
        unsigned int connection_max;
        unsigned int connection_num;

        /*
         *
         */
        unsigned int thread_min;
        unsigned int thread_num;

        unsigned int thread_max_fd;

        /*
         * List of connection set associated with this server.
         */
        pthread_mutex_t mutex;
        prelude_list_t free_set_list;
        prelude_list_t used_set_list;

        volatile sig_atomic_t continue_processing;
};




static inline void add_connection_to_tbl(server_logic_t *server, server_fd_set_t *set, server_logic_client_t *client)
{
        /*
         * We should never enter here if there is no free fd.
         */
        assert(set->used_index < server->thread_max_fd);

        client->key = set->used_index;

        /*
         * Client fd / data should always be -1 / NULL at this time.
         */
        assert(set->pfd[client->key].fd == -1);
        assert(set->client[client->key] == NULL);

        /*
         * Setup This connection.
         */
        client->set = set;
        client->event_flags = LOGIC_FLAGS_READ;
        set->client[client->key] = client;

        set->used_index++;
        set->rescan_pfd = TRUE;
}




static void remove_connection_from_tbl(server_logic_t *server, server_fd_set_t *set, int cnx_key)
{
        int key;

        key = --set->used_index;
        assert(cnx_key <= key);

        /*
         * Exchange our removed connection data, with the data
         * from the latest added connection.
         */
        if ( cnx_key < key ) {
                set->client[cnx_key] = set->client[key];
                set->client[cnx_key]->key = cnx_key;
                set->pfd[cnx_key].fd = set->pfd[key].fd;
                set->pfd[cnx_key].events = set->pfd[key].events;
        }

        /*
         * From The Single UNIX Specification, Version 2 :
         *
         * If the value of fd is less than 0,
         * events is ignored and revents is set to 0 in that entry on return from poll().
         */
        set->pfd[key].fd = -1;
        set->client[key] = NULL;

        server->connection_num--;
}




static inline int increase_connection_count_if_possible(server_logic_t *server)
{
        if ( server->connection_max && server->connection_num == server->connection_max )
                return -1;

        server->connection_num++;

        return 0;
}



static inline void add_set_to_free_list(server_logic_t *server, server_fd_set_t *set)
{
        dprint("thread=%ld, Adding to list, used_index=%d, thread_num=%d.\n",
               set->thread, set->used_index, server->thread_num);

        prelude_list_del(&set->list);
        prelude_list_add_tail(&server->free_set_list, &set->list);
}




static void update_fd_set_status(server_logic_t *server, server_fd_set_t *set)
{
        /*
         * If we can accept connection again, put this set into our free set list.
         */
        if ( set->used_index == (server->thread_max_fd - 1) )
                add_set_to_free_list(server, set);
}



static int remove_connection(server_fd_set_t *set, int cnx_key)
{
        int ret;
        server_logic_t *server = set->parent;

        dprint("removing connection\n");

        /*
         * Close the file descriptor associated with this set.
         */
        ret = server->close(server->sdata, set->client[cnx_key]);
        if ( ret < 0 ) {
                dprint("remove connection not completed\n");
                return ret;
        }

        /*
         * As of now we need to obtain the server lock because
         * we may modify shared data
         */
        pthread_mutex_lock(&server->mutex);

        remove_connection_from_tbl(server, set, cnx_key);
        update_fd_set_status(server, set);

        pthread_mutex_unlock(&server->mutex);

        return 0;
}



/*
 * This function should be called with the server lock held.
 * Uppon return, the lock will be released.
 */
static void add_connection(server_logic_t *server, server_fd_set_t *set, server_logic_client_t *client)
{
        add_connection_to_tbl(server, set, client);

        dprint("Adding connection, fd=%d, key=%d\n", prelude_io_get_fd(client->fd), client->key);

        /*
         * If the set is full, remove it from out list.
         * The list should be locked when this function is called !
         */
        if ( set->used_index == server->thread_max_fd ) {
                dprint("[%ld][%p] Max connection for this thread reached (%d).\n", set->thread, set, set->used_index);
                prelude_list_del(&set->list);
                prelude_list_add_tail(&server->used_set_list, &set->list);
        }
}


static int handle_fd_event(server_fd_set_t *set, int cnx_key)
{
        int ret = 0;

        assert(set->client[cnx_key]->key == cnx_key);

        if ( set->pfd[cnx_key].revents & POLLIN ) {
                ret = set->parent->read(set->parent->sdata, set->client[cnx_key]);
                dprint("thread=%ld: key=%d, fd=%d: Data available (ret=%d)\n", pthread_self(), cnx_key, set->pfd[cnx_key].fd, ret);
        }

        /*
         * POLLHUP and POLLOUT are mutually exclusive.
         * Only trigger remove_connection if we are certain there is no more data to be read (ret==0).
         */
        if ( ret == 0 && set->pfd[cnx_key].revents & (POLLERR|POLLHUP|POLLNVAL) ) {
                dprint("thread=%ld: key=%d, fd=%d: Hanging up.\n", pthread_self(), cnx_key, set->pfd[cnx_key].fd);
                ret = -1; /* trigger remove_connection() */
        }

        else if ( ret >= 0 && set->pfd[cnx_key].revents & POLLOUT ) {
                dprint("thread=%ld: key=%d, fd=%d: Output possible.\n", pthread_self(), cnx_key, set->pfd[cnx_key].fd);
                ret = set->parent->write(set->parent->sdata, set->client[cnx_key]);
        }

        return ret;
}



static void poll_fd_set(server_fd_set_t *set)
{
        struct timeval ts, te;
        int i, r = 0, ret, active_fd, index = set->used_index;
        server_logic_client_t *rescan[set->parent->thread_max_fd];

        dprint("polling %d entry\n", index);

        active_fd = poll(set->pfd, index, POLL_SLEEP_MS);
        if ( active_fd < 0 ) {
                if ( errno == EINTR )
                        return;

                prelude_log(PRELUDE_LOG_ERR, "error polling fd set: %s.\n", strerror(errno));
        }

        gettimeofday(&ts, NULL);

        /*
         * we need to scan through the whole array to handle LOGIC_FLAGS_CLOSING
         */
        for ( i = 0; i < index; i++ ) {
                /*
                 * This fd is currently ignored (-1).
                 */
                if ( set->pfd[i].fd != -1 && ! (set->client[i]->event_flags & LOGIC_FLAGS_CLOSING) ) {
                        ret = handle_fd_event(set, i);
                        if ( ret > 0 )
                                rescan[r++] = set->client[i];

                        if ( ret < 0 )
                                set->client[i]->event_flags |= LOGIC_FLAGS_CLOSING;
                }

                if ( set->client[i]->event_flags & LOGIC_FLAGS_CLOSING ) {
                        ret = remove_connection(set, i);
                        if ( ret == 0 ) {
                                index--;
                                i--;
                        }
                }
        }

        while ( r && ! set->rescan_pfd ) {
                for ( i = 0; i < r; i++ ) {
                        ret = handle_fd_event(set, rescan[i]->key);
                        if ( ret < 0 ) {
                                rescan[i]->event_flags |= LOGIC_FLAGS_CLOSING;
                                remove_connection(set, rescan[i]->key);
                        }

                        if ( ret <= 0 )
                                rescan[i] = rescan[--r];
                }

                gettimeofday(&te, NULL);
                if ( te.tv_sec != ts.tv_sec || (te.tv_usec - ts.tv_usec) > POLL_SLEEP_MS )
                        break;
        }
}



static void destroy_fd_set(server_logic_t *server, server_fd_set_t *set)
{
        int i;

        dprint("killing thread %ld on exit request.\n", set->thread);

        prelude_list_del(&set->list);
        server->thread_num--;

        pthread_mutex_unlock(&set->parent->mutex);

        for ( i = 0; i < set->used_index; i++ )
                server->close(server->sdata, set->client[i]);

        pthread_cond_destroy(&set->startup_cond);
        pthread_mutex_destroy(&set->startup_mutex);

        free(set->pfd);
        free(set->client);
        free(set);
}



static void *child_reader(void *ptr)
{
        int i;
        time_t now;
        sigset_t s;
        server_fd_set_t *set = ptr;

        pthread_detach(set->thread);
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

        sigfillset(&s);
        pthread_sigmask(SIG_SETMASK, &s, NULL);

        /*
         * signal that we are ready to get connection.
         */
        pthread_mutex_lock(&set->startup_mutex);
        pthread_cond_signal(&set->startup_cond);
        pthread_mutex_unlock(&set->startup_mutex);

        while ( set->parent->continue_processing ) {

                now = time(NULL);

                pthread_mutex_lock(&set->parent->mutex);

                if ( set->used_index )
                        set->last_time_used = now;

                else if ( set->parent->thread_num > set->parent->thread_min ) {
                        if ( now - set->last_time_used >= EMPTY_THREAD_TTL ) {
                                destroy_fd_set(set->parent, set);
                                break;
                        }
                }

                if ( set->rescan_pfd ) {
                        dprint("Updating polled entry.\n");

                        for ( i = 0; i < set->used_index; i++ ) {
                                /*
                                 * Update the pfd events field to include latest
                                 * modification made (possibly from another thread) if needed.
                                 */
                                set->pfd[i].events = 0;

                                if ( set->client[i]->event_flags & LOGIC_FLAGS_WRITE )
                                        set->pfd[i].events |= POLLOUT;
                                else
                                        set->pfd[i].events &= ~POLLOUT;

                                if ( set->client[i]->event_flags & LOGIC_FLAGS_READ )
                                        set->pfd[i].events |= POLLIN;
                                else
                                        set->pfd[i].events &= ~POLLIN;

                                if ( ! (set->client[i]->event_flags & LOGIC_FLAGS_CLOSING) )
                                        set->pfd[i].fd = prelude_io_get_fd(set->client[i]->fd);
                        }

                        set->rescan_pfd = FALSE;
                }

                pthread_mutex_unlock(&set->parent->mutex);
                poll_fd_set(set);
        }

        pthread_exit(NULL);

        return NULL; /* not needed, but avoid a warning. */
}



static server_fd_set_t *create_fd_set(server_logic_t *server)
{
        int i;
        server_fd_set_t *new;

        new = malloc(sizeof(*new));
        if ( ! new ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->pfd = malloc(sizeof(struct pollfd) * server->thread_max_fd);
        if ( ! new->pfd ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                free(new);
                return NULL;
        }

        new->client = malloc(sizeof(new->client) * server->thread_max_fd);
        if ( ! new->client ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                free(new->pfd);
                free(new);
                return NULL;
        }

        new->used_index = 0;
        new->parent = server;
        new->last_time_used = time(NULL);

        pthread_cond_init(&new->startup_cond, NULL);
        pthread_mutex_init(&new->startup_mutex, NULL);

        for ( i = 0; i < server->thread_max_fd; i++ ) {
                new->pfd[i].fd = -1;
                new->pfd[i].revents = 0;
                new->client[i] = NULL;
        }

        pthread_mutex_lock(&server->mutex);
        prelude_list_add_tail(&server->free_set_list, &new->list);
        pthread_mutex_unlock(&server->mutex);

        return new;
}



static int start_fd_set_thread(server_logic_t *server, server_fd_set_t *set)
{
        int ret;

        pthread_mutex_lock(&set->startup_mutex);

        ret = pthread_create(&set->thread, NULL, &child_reader, set);
        if ( ret < 0 ) {
                pthread_mutex_unlock(&set->startup_mutex);
                prelude_log(PRELUDE_LOG_ERR, "couldn't create thread.\n");
                return -1;
        }

        /*
         * wait for the thread to be started.
         */
        pthread_cond_wait(&set->startup_cond, &set->startup_mutex);

        pthread_mutex_unlock(&set->startup_mutex);
        pthread_cond_destroy(&set->startup_cond);
        pthread_mutex_destroy(&set->startup_mutex);

        server->thread_num++;

        dprint("Created thread %ld (used=%d)\n", set->thread, set->used_index);

        return 0;
}


static void logic_modify_flags(server_logic_client_t *fd, int flags)
{
        server_fd_set_t *set = fd->set;

        pthread_mutex_lock(&set->parent->mutex);
        fd->event_flags = flags;
        set->rescan_pfd = TRUE;
        pthread_mutex_unlock(&set->parent->mutex);
}



/*
 * server_process_requests:
 * @server; The server identifier.
 * @cfd: The client file descriptor to be handled.
 * @cdata: This file descriptor related private data.
 *
 * Add the 'cfd' file descriptor for handling.
 *
 * Returns: 0 on success, -1 otherwise.
 */
int server_logic_process_requests(server_logic_t *server, server_logic_client_t *client)
{
        int ret;
        server_fd_set_t *set;

        /*
         * Hold the list lock until we add the connection.
         * Because adding a connection could have the side effect of modifying
         * the content of the list. (while a connection could be removed. Same
         * side effect).
         */
        pthread_mutex_lock(&server->mutex);

        if ( increase_connection_count_if_possible(server) < 0 ) {
                pthread_mutex_unlock(&server->mutex);
                return -1;
        }

        if ( ! prelude_list_is_empty(&server->free_set_list) ) {
                set = prelude_list_entry(server->free_set_list.next, server_fd_set_t, list);
                add_connection(server, set, client);

                pthread_mutex_unlock(&server->mutex);

        } else {
                pthread_mutex_unlock(&server->mutex);

                set = create_fd_set(server);
                if ( ! set )
                        return -1;

                add_connection(server, set, client);

                ret = start_fd_set_thread(server, set);
                if ( ret < 0 ) {
                        destroy_fd_set(server, set);
                        return -1;
                }
        }

        return 0;
}




/**
 * server_logic_stop:
 * @server: Pointer on a #server_logic_t object.
 *
 * Signal to the server thread(s) that they should stop
 * processing requests.
 */
void server_logic_stop(server_logic_t *server)
{
        pthread_mutex_lock(&server->mutex);
        server->continue_processing = 0;
        pthread_mutex_unlock(&server->mutex);
}



/**
 * server_logic_destroy:
 * @server: Pointer on a #server_logic_t object.
 *
 * Destroy the @server object.
 *
 * Warning: in the current state, server_logic_destroy() should only be
 * used if server_logic_process_requests() was not yet called.
 */
void server_logic_destroy(server_logic_t *server)
{
        pthread_mutex_destroy(&server->mutex);
        free(server);
}



/**
 * server_logic_set_max_connection:
 * @server: Pointer on a #server_logic_t object.
 * @max: Maximum number of connection handled by @server.
 *
 * Tell server-logic not to handle more than @max connection.
 * The default is zero, meaning there is no limit.
 */
void server_logic_set_max_connection(server_logic_t *server, unsigned int max)
{
        server->connection_max = max;
}




/**
 * server_logic_set_min_running_thread:
 * @server: Pointer on a #server_logic_t object.
 * @min:
 *
 */
void server_logic_set_min_running_thread(server_logic_t *server, unsigned int min)
{
        server->thread_min = min;
}



/**
 * server_logic_set_max_fd_by_thread:
 * @server: Pointer on a #server_logic_t object.
 * @max:
 *
 */
void server_logic_set_max_fd_by_thread(server_logic_t *server, unsigned int max)
{
        server->thread_max_fd = max;
}




/*
 * server_logic_new:
 * @sdata: Pointer to the server data.
 * @s_read: The read function to be called back on input.
 * @s_close: The close function to be called on hang up.
 *
 * Returns: A pointer to a new server_logic_t, NULL on error.
 */
server_logic_t *server_logic_new(void *sdata, server_logic_read_t *s_read,
                                 server_logic_write_t *s_write, server_logic_close_t *s_close)
{
        server_logic_t *new;

        new = malloc(sizeof(server_logic_t));
        if ( ! new )
                return NULL;

        prelude_list_init(&new->free_set_list);
        prelude_list_init(&new->used_set_list);
        pthread_mutex_init(&new->mutex, NULL);

        new->sdata = sdata;
        new->read = s_read;
        new->write = s_write;
        new->close = s_close;

        new->thread_num = 0;
        new->connection_num = 0;

        new->thread_min = DEFAULT_MIN_THREAD;
        new->connection_max = DEFAULT_MAX_CONNECTION;
        new->thread_max_fd = DEFAULT_MAX_FD_BY_THREAD;
        new->continue_processing = 1;

        return new;
}



/**
 * server_logic_remove_client:
 * @client:
 *
 */
int server_logic_remove_client(server_logic_client_t *client)
{
        if ( client->key < 0 )
                return -1;

        logic_modify_flags(client, client->event_flags | LOGIC_FLAGS_CLOSING);
        return 0;
}



void server_logic_notify_write_enable(server_logic_client_t *fd)
{
        logic_modify_flags(fd, fd->event_flags | LOGIC_FLAGS_WRITE);
}



void server_logic_notify_write_disable(server_logic_client_t *fd)
{
        logic_modify_flags(fd, fd->event_flags & ~LOGIC_FLAGS_WRITE);
}



void server_logic_notify_read_enable(server_logic_client_t *fd)
{
        logic_modify_flags(fd, fd->event_flags | LOGIC_FLAGS_READ);
}



void server_logic_notify_read_disable(server_logic_client_t *fd)
{
        logic_modify_flags(fd, fd->event_flags & ~LOGIC_FLAGS_READ);
}





