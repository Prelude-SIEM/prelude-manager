/*****
*
* Copyright (C) 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#include <libprelude/list.h>
#include <libprelude/common.h>
#include <libprelude/prelude-io.h>

#include "server-logic.h"


/*
 * If modifying this value, beside 128, carefull
 * to not use an uint8_t for the free_tbl and free_index members
 * to avoid wrap arround.
 */
#define MAX_FD_BY_THREAD 100


#ifdef DEBUG
 #define dprint(args...) printf(args)
#else
 #define dprint(args...)
#endif



typedef struct {
        struct list_head list;

        /*
         * Thread handling this set of file descriptor.
         */
        pthread_t thread;        
        pthread_mutex_t set_mutex;

        /*
         * Array containing client / file descriptor polling related data.
         */
        void *clientdata[MAX_FD_BY_THREAD];
        prelude_io_t *pio[MAX_FD_BY_THREAD];
        struct pollfd pfd[MAX_FD_BY_THREAD];
        
        /*
         * Array containing key to free client data / pfd.
         */
        uint8_t free_index;
        uint8_t free_tbl[MAX_FD_BY_THREAD];
        
} server_fd_set_t;



struct server_struct {

        void *sdata;
        
        server_read_func_t *read;
        server_close_func_t *close;

        /*
         * List of connection set associated with this server.
         */
        struct list_head free_set_list;
        pthread_mutex_t free_set_list_mutex;

        /*
         * Only to be used uppon new thread creation.
         */
        server_fd_set_t *new_set;
};

        


static void remove_connection(server_t *server, server_fd_set_t *set, int cnx_key) 
{        
        /*
         * Close the file descriptor associated with this set.
         * Handle the case where close could be interrupted.
         */
        server->close(set->pio[cnx_key], set->clientdata[cnx_key]);
        

        /*
         * From The Single UNIX Specification, Version 2 :
         *
         * If the value of fd is less than 0,
         * events is ignored and revents is set to 0 in that entry on return from poll().
         */
        set->pfd[cnx_key].fd = -1;
        set->pio[cnx_key] = NULL;
        set->clientdata[cnx_key] = NULL;

        
        /*
         * Lock the list before locking the thread mutex,
         * to prevent a race with a connection on the way to be added
         * (list already locked and this set obtained from the list,
         * then add_connection() waiting on this set mutex while we are killing
         * the set because there is no more FD used.
         */
        pthread_mutex_lock(&server->free_set_list_mutex);
        pthread_mutex_lock(&set->set_mutex);
        
        /*
         * Add this connection index to our free connection array.
         * Increase the connection index when done.
         */
        set->free_tbl[set->free_index++] = cnx_key;
        
        
        /*
         * If we can accept connection again,
         * put this set into our free FD list.
         */
        if ( set->free_index == 1 ) {
                dprint("thread=%ld, Adding to list.\n", pthread_self());
                list_add_tail(&set->list, &server->free_set_list);
        }

        /*
         * If there is no more used fd, kill this set.
         */
        else if ( set->free_index == MAX_FD_BY_THREAD ) {
                
                list_del(&set->list);
                
                pthread_mutex_unlock(&set->set_mutex);
                pthread_mutex_unlock(&server->free_set_list_mutex);
                
                pthread_mutex_destroy(&set->set_mutex);

                free(set);

                dprint("Killing thread %ld\n", pthread_self());
                pthread_exit(NULL);
        }
        
        pthread_mutex_unlock(&set->set_mutex);
        pthread_mutex_unlock(&server->free_set_list_mutex);
}




static void add_connection(server_fd_set_t *set, prelude_io_t *pio, void *cdata)
{
        int key;

        
        pthread_mutex_lock(&set->set_mutex);
        
        /*
         * We should never enter here if there is no free fd.
         */
        assert(set->free_index > 0);

        /*
         * Decrease index then get a free connection entry index.
         */
        key = set->free_tbl[--set->free_index];
        
        /*
         * Are we still able to accept connection ?
         */
        if ( set->free_index == 0 ) {
                dprint("Max connection for this thread reached (%d).\n", set->free_index);

                /*
                 * We are not, remove this set from our list.
                 * The list should be locked when this function is called !
                 */
                list_del(&set->list);
        }
        
        pthread_mutex_unlock(&set->set_mutex);

        /*
         * Client fd / data should always be -1 / NULL at this time.
         */
        assert(set->pfd[key].fd == -1);
        assert(set->pio[key] == NULL);
        assert(set->clientdata[key] == NULL);
        
        /*
         * Setup This connection.
         */
        set->pio[key] = pio;
        set->pfd[key].fd = prelude_io_get_fd(pio);
        set->pfd[key].events = POLLIN;
        set->clientdata[key] = cdata;
}




static int handle_fd_event(server_t *server, server_fd_set_t *set, int cnx_key) 
{        
        /*
         * Data is available on this fd,
         * call the user provided callback.
         */        
        if ( set->pfd[cnx_key].revents & POLLIN ) {
                int ret;
                
                ret = server->read(set->pio[cnx_key], &set->clientdata[cnx_key]);
                dprint("thread=%ld - Data availlable (ret=%d)\n", pthread_self(), ret);
                
                if ( ret < 0 )
                        remove_connection(server, set, cnx_key);

                return 0;
        }

        /*
         * Error or hangup occured. 
         */
        else {                
                dprint("thread=%ld - Hanging up.\n", pthread_self());
                remove_connection(server, set, cnx_key);
                return 0;
        }

        return -1;
}





static void *child_reader(void *ptr) 
{
        int i, ret, active_fd;
        server_t *server = ptr;
        struct pollfd pfd[MAX_FD_BY_THREAD];
        server_fd_set_t *set = server->new_set;
        
        while ( 1 ) {
                /*
                 * Is there a way to avoid this copy ?
                 */
                pthread_mutex_lock(&set->set_mutex);
                memcpy(pfd, set->pfd, sizeof(pfd));
                pthread_mutex_unlock(&set->set_mutex);

                /*
                 * Use a one second timeout,
                 * in order to take new FD for this set into account.
                 */
                active_fd = poll(pfd, MAX_FD_BY_THREAD, 1000);                
                if ( active_fd < 0 ) {
                        if ( errno == EINTR ) 
                                continue;
                        
                        log(LOG_ERR, "error polling FDs set.\n");
                }

                else if ( active_fd == 0 ) 
                        continue; /* timeout */
                
                for ( i = 0; i < MAX_FD_BY_THREAD; i++ ) {
                        
                        /*
                         * This fd is ignored (-1) or nothing occured.
                         */
                        if ( pfd[i].fd < 0 || pfd[i].revents == 0)
                                continue;
                        
                        set->pfd[i].revents = pfd[i].revents;
                        
                        ret = handle_fd_event(server, set, i);
                        if ( ret == 0 )
                                active_fd--;

                        pfd[i].revents = 0;
                        set->pfd[i].revents = 0;
                }
        }
}




static server_fd_set_t *create_fd_set(server_t *server) 
{
        int ret, i;
        server_fd_set_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->free_index = MAX_FD_BY_THREAD;
        
        for ( i = 0; i < MAX_FD_BY_THREAD; i++ ) {
                new->pio[i] = NULL;
                new->pfd[i].fd = -1;
                new->clientdata[i] = NULL;
                new->free_tbl[i] = i;
        }

        pthread_mutex_init(&new->set_mutex, NULL);

        list_add_tail(&new->list, &server->free_set_list);

        server->new_set = new;
        
        ret = pthread_create(&new->thread, NULL, &child_reader, server);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't create thread.\n");
                return NULL;
        }

        pthread_detach(new->thread);
        
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
int server_logic_process_requests(server_t *server, prelude_io_t *pio, void *cdata) 
{
        server_fd_set_t *set;
        
        /*
         * Hold the list lock until we add the connection.
         * Because adding a connection could have the side effect of modifying
         * the content of the list. (while a connection could be removed. Same
         * side effect).
         */
        pthread_mutex_lock(&server->free_set_list_mutex);
        
        if ( list_empty(&server->free_set_list) ) {
                
                pthread_mutex_unlock(&server->free_set_list_mutex);
                
                set = create_fd_set(server);
                if ( ! set ) 
                        return -1;

                /*
                 * add_connection should never call
                 * list_del() at this time, so we don't need locking.
                 */
                add_connection(set, pio, cdata);
        } else {
                set = list_entry(server->free_set_list.next, server_fd_set_t, list);
                add_connection(set, pio, cdata);
                pthread_mutex_unlock(&server->free_set_list_mutex);
        }
        
        return 0;
}





/*
 * server_logic_stop:
 * @server: The server to stop.
 */
int server_logic_stop(server_t *server) 
{
        /*
         * Not implemented. Yet.
         */

        return 0;
}





/*
 * server_logic_new:
 * @s_read: The read function be called back on input.
 * @s_close: The close function to be called on hang up.
 *
 * Returns: A pointer to a new server_t, NULL on error.
 */
server_t *server_logic_new(server_read_func_t *s_read, server_close_func_t *s_close) 
{
        server_t *new;

        new = malloc(sizeof(server_t));
        if ( ! new )
                return NULL;

        INIT_LIST_HEAD(&new->free_set_list);
        pthread_mutex_init(&new->free_set_list_mutex, NULL);

        new->read = s_read;
        new->close = s_close;

        return new;
}

