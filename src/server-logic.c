/*****
*
* Copyright (C) 2001, 2002, 2003 Yoann Vandoorselaere <yoann@prelude-ids.org>
* All Rights Reserved
*
* This file is part of the Prelude program.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <pthread.h>
#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>
#include <libprelude/threads.h>

#include "server-logic.h"


#define DEFAULT_MIN_THREAD         1
#define DEFAULT_MAX_CONNECTION     0

/*
 * If modifying this value beside 256, take care
 * about the size of the sig_atomic_t index, which could be
 * only 8 bits long on some architecture.
 */
#define DEFAULT_MAX_FD_BY_THREAD 100


#ifdef DEBUG
 #define dprint(args...) fprintf(stderr, args)
#else
 #define dprint(args...)
#endif


struct server_logic_client {
        SERVER_LOGIC_CLIENT_OBJECT;
};



typedef struct server_fd_set {
        struct list_head list;

        /*
         * Thread handling this set of file descriptor.
         */
        pthread_t thread;

        /*
         * Used on startup
         */
        pthread_cond_t startup_cond;
        pthread_mutex_t startup_mutex;
        
        /*
         * Array containing client / file descriptor polling related data.
         */
        struct pollfd *pfd;
        server_logic_client_t **client;
        
        /*
         * Index used to address free client data / pfd.
         */
        volatile sig_atomic_t used_index;

        server_logic_t *parent;
} server_fd_set_t;



struct server_logic {
        void *sdata;
                
        server_logic_read_t *read;
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
        struct list_head free_set_list;
        struct list_head used_set_list;
};




static void restart_poll(int signo) 
{
        /*
         * do nothing here.
         * this is the signal handler for SIGUSR1 which we use in order to
         * interrupt poll, for new connection notification.
         */
        dprint("[thread=%ld] interrupted by sig %d.\n", pthread_self(), signo);
}




static inline void add_connection_to_tbl(server_logic_t *server, server_fd_set_t *set, server_logic_client_t *client)
{
        /*
         * We should never enter here if there is no free fd.
         */
        assert(set->used_index < server->thread_max_fd);
        client->key = set->used_index++;
        client->set = set;
}




static void remove_connection_from_tbl(server_logic_t *server, server_fd_set_t *set, int cnx_key) 
{
        int key;
        
        key = --set->used_index;

        /*
         * Exchange our removed connection data, with the data
         * from the latest added connection.
         */
        if ( key != cnx_key ) {
                set->client[cnx_key] = set->client[key];
                set->pfd[cnx_key].fd = set->pfd[key].fd;
                set->client[cnx_key]->key = cnx_key;
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

        list_del(&set->list);
        list_add_tail(&set->list, &server->free_set_list);
}




static void update_fd_set_status(server_logic_t *server, server_fd_set_t *set) 
{        
        /*
         * If we can accept connection again, put this set into our free set list.
         */
        if ( set->used_index == (server->thread_max_fd - 1) ) 
                add_set_to_free_list(server, set);
        
        /*
         * If there is no more used fd, kill this set.
         */
        else if ( set->used_index == 0 && server->thread_num > server->thread_min ) {

                pthread_t thread = set->thread;
                
                list_del(&set->list);
                server->thread_num--;
                pthread_mutex_unlock(&server->mutex);
                
                dprint("Killing thread %ld\n", thread);
                
                free(set);
                pthread_cancel(thread);
        }
}



static void remove_connection(server_fd_set_t *set, int cnx_key) 
{
        server_logic_t *server = set->parent;

        dprint("removing connection\n");
        
        /*
         * Close the file descriptor associated with this set.
         */
        server->close(server->sdata, set->client[cnx_key]);
        
        /*
         * As of now we need to obtain the server lock because
         * we may modify shared data
         */
        pthread_mutex_lock(&server->mutex);
        
        remove_connection_from_tbl(server, set, cnx_key);
        update_fd_set_status(server, set);
        
        pthread_mutex_unlock(&server->mutex);
}




/*
 * This function should be called with the server lock held.
 * Uppon return, the lock will be released.
 */
static void add_connection(server_logic_t *server, server_fd_set_t *set, server_logic_client_t *client)
{
        add_connection_to_tbl(server, set, client);
        
        dprint("Adding connection to %ld, fd=%d, key=%d\n", set->thread, prelude_io_get_fd(client->fd), client->key);
        
        /*
         * If the set is full, remove it from out list.
         * The list should be locked when this function is called !
         */
        if ( set->used_index == server->thread_max_fd ) {
                dprint("[%ld][%p] Max connection for this thread reached (%d).\n", set->thread, set, set->used_index);
                list_del(&set->list);
                list_add_tail(&set->list, &server->used_set_list);
        }
        pthread_mutex_unlock(&server->mutex);

        /*
         * Client fd / data should always be -1 / NULL at this time.
         */
        assert(set->pfd[client->key].fd == -1);
        assert(set->client[client->key] == NULL);
        
        /*
         * Setup This connection.
         */
        set->pfd[client->key].fd = prelude_io_get_fd(client->fd);
        set->pfd[client->key].events = POLLIN;
        set->client[client->key] = client;
}




static int handle_fd_event(server_fd_set_t *set, int cnx_key) 
{ 
        assert(set->client[cnx_key]->key == cnx_key);
        
        if ( set->pfd[cnx_key].revents & POLLIN ) {
                int ret;
                
                ret = set->parent->read(set->parent->sdata, set->client[cnx_key]);
                dprint("thread=%ld: key=%d, fd=%d: Data available (ret=%d)\n", pthread_self(), cnx_key, set->pfd[cnx_key].fd, ret);
                if ( ret < 0 )
                        remove_connection(set, cnx_key);
        }
        
        else if ( set->pfd[cnx_key].revents & (POLLERR|POLLHUP|POLLNVAL) ) {
                dprint("thread=%ld: key=%d, fd=%d: Hanging up.\n", pthread_self(), cnx_key, set->pfd[cnx_key].fd);
                remove_connection(set, cnx_key);
        }

        else
                return -1;

        return 0;
}



static void poll_fd_set(server_fd_set_t *set) 
{
        int i, active_fd, ret;
        
        dprint("polling %d first entry.\n", set->used_index);
                
        active_fd = poll(set->pfd, set->used_index, -1);                
        if ( active_fd < 0 ) {
                if ( errno == EINTR ) 
                        return;
                
                log(LOG_ERR, "error polling FDs set.\n");
        }
                
        for ( i = 0; i < set->parent->thread_max_fd && active_fd > 0; i++ ) {
                        
                /*
                 * This fd is currently ignored (-1).
                 */
                if ( set->pfd[i].fd < 0 )
                        continue;
                                                
                ret = handle_fd_event(set, i);
                if ( ret == 0 )
                        active_fd--;
        }
}



static void *child_reader(void *ptr) 
{
        int ret;
        sigset_t s;
        struct sigaction act;
        server_fd_set_t *set = ptr;

        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
        pthread_detach(set->thread);
        
        sigfillset(&s);
        sigdelset(&s, SIGUSR1);
        pthread_sigmask(SIG_SETMASK, &s, NULL);
        
        /*
         * We want to catch SIGUSR1, so that we know a new fd is in our set.
         */
        act.sa_flags = 0;
        sigemptyset(&act.sa_mask);
        act.sa_handler = restart_poll;

        ret = sigaction(SIGUSR1, &act, NULL);
        if ( ret < 0 ) {
                log(LOG_ERR, "failed to register thread handler for SIGUSR1.\n");
                return NULL;
        }

        /*
         * signal that we are ready to get connection.
         */
        pthread_mutex_lock(&set->startup_mutex);
        pthread_cond_signal(&set->startup_cond);
        pthread_mutex_unlock(&set->startup_mutex);
            
        while ( 1 ) 
                poll_fd_set(set);

        dprint("killing thread %ld on exit request.\n", set->thread);
        pthread_exit(NULL);

        return NULL; /* not needed, but avoid a warning. */
}



static void destroy_fd_set(server_logic_t *server, server_fd_set_t *set) 
{
        int i;
        
        pthread_cancel(set->thread);
        
        for ( i = 0; i < set->used_index; i++ )
                server->close(server->sdata, set->client[i]);

        free(set->pfd);
        free(set->client);
        free(set);
}



static server_fd_set_t *create_fd_set(server_logic_t *server) 
{
        int i;
        server_fd_set_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->pfd = malloc(sizeof(*new->pfd) * server->thread_max_fd);
        if ( ! new->pfd ) {
                log(LOG_ERR, "memory exhausted.\n");
                free(new);
                return NULL;
        }

        new->client = malloc(sizeof(new->client) * server->thread_max_fd);
        if ( ! new->client ) {
                log(LOG_ERR, "memory exhausted.\n");
                free(new->pfd);
                free(new);
                return NULL;
        }
        
        new->used_index = 0;
        new->parent = server;

        pthread_cond_init(&new->startup_cond, NULL);
        pthread_mutex_init(&new->startup_mutex, NULL);
        
        for ( i = 0; i < server->thread_max_fd; i++ ) {
                new->pfd[i].fd = -1;
                new->client[i] = NULL;
        }
        
        list_add_tail(&new->list, &server->free_set_list);
        
        return new;
}



static int start_fd_set_thread(server_logic_t *server, server_fd_set_t *set) 
{
        int ret;

        pthread_mutex_lock(&set->startup_mutex);
        
        ret = pthread_create(&set->thread, NULL, &child_reader, set);                
        if ( ret < 0 ) {
                pthread_mutex_unlock(&set->startup_mutex);
                log(LOG_ERR, "couldn't create thread.\n");
                return -1;
        }
                
        dprint("Created thread %ld (used=%d)\n", set->thread, set->used_index);

        /*
         * wait for the thread to be started.
         */
        pthread_cond_wait(&set->startup_cond, &set->startup_mutex);
        
        pthread_mutex_unlock(&set->startup_mutex);
        pthread_cond_destroy(&set->startup_cond);
        pthread_mutex_destroy(&set->startup_mutex);

        server->thread_num++;
        
        return 0;
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
        
        if ( ! list_empty(&server->free_set_list) ) {
                set = list_entry(server->free_set_list.next, server_fd_set_t, list);

                add_connection(server, set, client);
                
                /*
                 * Notify the thread that may be polling our set that a new connection
                 * is arrived into the set and should be taken into account.
                 */
                pthread_kill(set->thread, SIGUSR1);        
                
        } else {
                
                set = create_fd_set(server);
                if ( ! set ) 
                        return -1;
                
                ret = start_fd_set_thread(server, set);
                if ( ret < 0 ) {
                        destroy_fd_set(server, set);
                        return -1;
                }
                
                add_connection(server, set, client);
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
        server_fd_set_t *set;
        struct list_head *tmp, *bkp;

        pthread_mutex_lock(&server->mutex);
        
        list_for_each_safe(tmp, bkp, &server->used_set_list) {
                set = list_entry(tmp, server_fd_set_t, list);
                destroy_fd_set(server, set);
        }

        list_for_each_safe(tmp, bkp, &server->free_set_list) {
                set = list_entry(tmp, server_fd_set_t, list);
                destroy_fd_set(server, set);
        }

        pthread_mutex_unlock(&server->mutex);
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



/**
 * server_logic_remove_client:
 * @client:
 *
 */
void server_logic_remove_client(server_logic_client_t *client) 
{
        remove_connection(client->set, client->key);
}




/*
 * server_logic_new:
 * @sdata: Pointer to the server data.
 * @s_read: The read function to be called back on input.
 * @s_close: The close function to be called on hang up.
 *
 * Returns: A pointer to a new server_logic_t, NULL on error.
 */
server_logic_t *server_logic_new(void *sdata,
                                 server_logic_read_t *s_read, server_logic_close_t *s_close) 
{
        server_logic_t *new;

        new = malloc(sizeof(server_logic_t));
        if ( ! new )
                return NULL;

        INIT_LIST_HEAD(&new->free_set_list);
        INIT_LIST_HEAD(&new->used_set_list);
        pthread_mutex_init(&new->mutex, NULL);

        new->sdata = sdata;
        new->read = s_read;
        new->close = s_close;
        
        new->thread_num = 0;
        new->connection_num = 0;
        
        new->thread_min = DEFAULT_MIN_THREAD;
        new->connection_max = DEFAULT_MAX_CONNECTION;
        new->thread_max_fd = DEFAULT_MAX_FD_BY_THREAD;
        
        return new;
}




