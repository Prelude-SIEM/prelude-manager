/*****
*
* Copyright (C) 2001, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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


#ifdef DEBUG
 #define dprint(args...) fprintf(stderr, args)
#else
 #define dprint(args...)
#endif



/*
 * If modifying this value beside 256, carefull
 * to not use an uint8_t for the free_tbl and free_index members
 * to avoid wrap arround.
 */
#define MAX_FD_BY_THREAD 100



struct server_logic_client {
        SERVER_LOGIC_CLIENT_OBJECT;
};



typedef struct {
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
        struct pollfd pfd[MAX_FD_BY_THREAD];
        server_logic_client_t *client[MAX_FD_BY_THREAD];
        
        /*
         * Array containing key to free client data / pfd.
         */
        uint8_t used_index;
        uint8_t free_tbl[MAX_FD_BY_THREAD];

        server_logic_t *parent;
} server_fd_set_t;



struct server_logic {
        void *sdata;
        
        volatile sig_atomic_t continue_processing;
        
        server_logic_read_t *read;
        server_logic_close_t *close;

        /*
         * List of connection set associated with this server.
         */
        pthread_mutex_t mutex;
        struct list_head free_set_list;
};




static void restart_poll(int signo) 
{
        /*
         * do nothing here.
         * this is the signal handler for SIGUSR1 which we use in order to
         * interrupte poll, for new connection notification.
         */
        dprint("thread=%ld - interrupted by signal %d.\n", pthread_self(), signo);
}





static void remove_connection(server_fd_set_t *set, int cnx_key) 
{
        server_logic_t *server = set->parent;
        
        /*
         * Close the file descriptor associated with this set.
         */
        server->close(server->sdata, set->client[cnx_key]);
        

        /*
         * From The Single UNIX Specification, Version 2 :
         *
         * If the value of fd is less than 0,
         * events is ignored and revents is set to 0 in that entry on return from poll().
         */
        set->pfd[cnx_key].fd = -1;
        set->client[cnx_key] = NULL;

        
        /*
         * As of now we need to obtain the server lock because
         * we may modify shared data
         */
        pthread_mutex_lock(&server->mutex);
        
        /*
         * Decrease the used index *before* adding our connection
         * index to the free connection table. So that used_index
         * point to a free entry after the change.
         */
        set->free_tbl[--set->used_index] = cnx_key;
        
        /*
         * If we can accept connection again, put this set into our free set list.
         */
        if ( set->used_index == (MAX_FD_BY_THREAD - 1) ) {
                dprint("thread=%ld, Adding to list.\n", pthread_self());
                list_add_tail(&set->list, &server->free_set_list);
        }

        
        /*
         * If there is no more used fd, kill this set.
         * FIXME: we should keep it arround.
         */
        else if ( set->used_index == 0 ) {
                list_del(&set->list);
                pthread_mutex_unlock(&server->mutex);
                
                dprint("Killing thread %ld\n", pthread_self());
                
                free(set);
                pthread_exit(NULL);
        }

        pthread_mutex_unlock(&server->mutex);
}



/*
 * This function should be called with the server lock held.
 * Uppon return, the lock will be released.
 */
static void add_connection(server_logic_t *server, server_fd_set_t *set, server_logic_client_t *client)
{
        int key;

        dprint("Adding connection to %ld\n", set->thread);
        
        /*
         * We should never enter here if there is no free fd.
         */
        assert(set->used_index < MAX_FD_BY_THREAD);

        /*
         * get a free connection entry then increase used connection index.
         */
        key = set->free_tbl[set->used_index++];
        
        /*
         * Are we still able to accept connection ?
         */
        if ( set->used_index == MAX_FD_BY_THREAD ) {
                dprint("[%ld][%p] Max connection for this thread reached (%d).\n", set->thread, set, set->used_index);
                
                /*
                 * We are not, remove this set from our list.
                 * The list should be locked when this function is called !
                 */
                list_del(&set->list);
        }
        pthread_mutex_unlock(&server->mutex);

        /*
         * Client fd / data should always be -1 / NULL at this time.
         */
        assert(set->pfd[key].fd == -1);
        assert(set->client[key] == NULL);
        
        /*
         * Setup This connection.
         */
        set->pfd[key].fd = prelude_io_get_fd(client->fd);
        set->pfd[key].events = POLLIN;
        set->client[key] = client;
}




static int handle_fd_event(server_fd_set_t *set, int cnx_key) 
{
        if ( set->pfd[cnx_key].revents & (POLLERR|POLLHUP|POLLNVAL) ) {
                dprint("thread=%ld - Hanging up.\n", pthread_self());
                remove_connection(set, cnx_key);
                return 0;
        }
                
        /*
         * Data is available on this fd,
         * call the user provided callback.
         */        
        else if ( set->pfd[cnx_key].revents & POLLIN ) {
                int ret;

                ret = set->parent->read(set->parent->sdata, set->client[cnx_key]);
                dprint("thread=%ld - Data available (ret=%d)\n", pthread_self(), ret);       
                if ( ret < 0 )
                        remove_connection(set, cnx_key);

                return 0;
        }

        return -1;
}





static void *child_reader(void *ptr) 
{
        sigset_t s;
        struct sigaction act;
        int i, ret, active_fd;
        server_fd_set_t *set = ptr;
        
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
        
        while ( set->parent->continue_processing ) {
                
                active_fd = poll(set->pfd, MAX_FD_BY_THREAD, -1);                
                if ( active_fd < 0 ) {
                        if ( errno == EINTR ) 
                                continue;
                        
                        log(LOG_ERR, "error polling FDs set.\n");
                }
                
                for ( i = 0; i < MAX_FD_BY_THREAD && active_fd > 0; i++ ) {
                        
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

        dprint("killing thread %ld on exit request.\n", set->thread);
        pthread_exit(NULL);
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

        new->used_index = 0;
        new->parent = server;

        pthread_cond_init(&new->startup_cond, NULL);
        pthread_mutex_init(&new->startup_mutex, NULL);
        
        for ( i = 0; i < MAX_FD_BY_THREAD; i++ ) {
                new->pfd[i].fd = -1;
                new->client[i] = NULL;
                new->free_tbl[i] = i;
        }
        
        list_add_tail(&new->list, &server->free_set_list);
        
        return new;
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

                add_connection(server, set, client);

                pthread_mutex_lock(&set->startup_mutex);
                ret = pthread_create(&set->thread, NULL, &child_reader, set);
                
                dprint("Created thread %ld (used=%d)\n", set->thread, set->used_index);
                
                if ( ret < 0 ) {
                        pthread_mutex_unlock(&set->startup_mutex);
                        log(LOG_ERR, "couldn't create thread.\n");
                        return -1;
                }

                /*
                 * wait for the thread to be started.
                 */
                pthread_cond_wait(&set->startup_cond, &set->startup_mutex);
                pthread_mutex_unlock(&set->startup_mutex);
                pthread_cond_destroy(&set->startup_cond);
                pthread_mutex_destroy(&set->startup_mutex);
        } 
                
        return 0;
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
        pthread_mutex_init(&new->mutex, NULL);

        new->sdata = sdata;
        new->read = s_read;
        new->close = s_close;
        new->continue_processing = 1;
        
        return new;
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
        server->continue_processing = 0;
}



