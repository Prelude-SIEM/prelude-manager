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
        struct pollfd pfd[MAX_FD_BY_THREAD];
        
        /*
         * Array containing key to free client data / pfd.
         */
        uint8_t free_index;
        uint8_t free_tbl[MAX_FD_BY_THREAD];
        
} manager_fd_set_t;

        

/*
 * This list contain pointer to set that have available space.
 */
static LIST_HEAD(free_fd_list);
static pthread_mutex_t list_mutex;
static int (*data_available_cb)(int fd, void *clientdata);



static void remove_connection(manager_fd_set_t *set, int cnx_key) 
{
        int ret;

        /*
         * Close the file descriptor associated with this set.
         * Handle the case where close could be interrupted.
         */
        do {
                ret = close(set->pfd[cnx_key].fd);
        } while ( ret < 0 && errno == EINTR );

        /*
         * From The Single UNIX Specification, Version 2 :
         *
         * If the value of fd is less than 0,
         * events is ignored and revents is set to 0 in that entry on return from poll().
         */
        set->pfd[cnx_key].fd = -1;
        set->clientdata[cnx_key] = NULL;

        
        /*
         * Lock the list before locking the thread mutex,
         * to prevent a race with a connection on the way to be added
         * (list already locked and this set obtained from the list,
         * then add_connection() waiting on this set mutex while we are killing
         * the set because there is no more FD used.
         */
        pthread_mutex_lock(&list_mutex);
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
                list_add_tail(&set->list, &free_fd_list);
        }

        /*
         * If there is no more used fd, kill this set.
         */
        else if ( set->free_index == MAX_FD_BY_THREAD ) {
                
                list_del(&set->list);
                
                pthread_mutex_unlock(&set->set_mutex);
                pthread_mutex_unlock(&list_mutex);
                
                pthread_mutex_destroy(&set->set_mutex);

                free(set);

                dprint("Killing thread %ld\n", pthread_self());
                pthread_exit(NULL);
        }
        
        pthread_mutex_unlock(&set->set_mutex);
        pthread_mutex_unlock(&list_mutex);
}



static void add_connection(manager_fd_set_t *set, int fd, void *clientdata) 
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
        assert(set->clientdata[key] == NULL);
        
        /*
         * Setup This connection.
         */
        set->pfd[key].fd = fd;
        set->pfd[key].events = POLLIN;
        set->clientdata[key] = clientdata;
}




static int handle_fd_event(manager_fd_set_t *set, int cnx_key) 
{        
        /*
         * Data is available on this fd,
         * call the user provided callback.
         */        
        if ( set->pfd[cnx_key].revents & POLLIN ) {
                int ret;
                
                ret = data_available_cb(set->pfd[cnx_key].fd, set->clientdata[cnx_key]);
                dprint("thread=%ld - Data availlable (ret=%d)\n", pthread_self(), ret);
                
                if ( ret < 0 )
                        remove_connection(set, cnx_key);

                return 0;
        }

        /*
         * Error or hangup occured. 
         */
        else {
                dprint("thread=%ld - Hanging up.\n", pthread_self());
                remove_connection(set, cnx_key);
                return 0;
        }

        return -1;
}





static void *child_reader(void *ptr) 
{
        int i, ret, active_fd;
        manager_fd_set_t *set = ptr;
        struct pollfd pfd[MAX_FD_BY_THREAD];
        
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
                        
                        log(LOG_ERR, "Error polling FDs set.\n");
                }

                else if ( active_fd == 0 ) 
                        continue; /* timeout */
                
                for ( i = 0; i < MAX_FD_BY_THREAD && active_fd > 0; i++ ) {
                        
                        /*
                         * This fd is ignored (-1) or nothing occured.
                         */
                        if ( pfd[i].fd < 0 || pfd[i].revents == 0)
                                continue;

                        set->pfd[i].revents = pfd[i].revents;
                        
                        ret = handle_fd_event(set, i);
                        if ( ret == 0 )
                                active_fd--;
                }
        }
}




static manager_fd_set_t *create_fd_set(void) 
{
        int ret, i;
        manager_fd_set_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->free_index = MAX_FD_BY_THREAD;
        
        for ( i = 0; i < MAX_FD_BY_THREAD; i++ ) {

                new->pfd[i].fd = -1;
                new->clientdata[i] = NULL;
                new->free_tbl[i] = i;
        }

        pthread_mutex_init(&new->set_mutex, NULL);
        
        list_add_tail(&new->list, &free_fd_list);

        ret = pthread_create(&new->thread, NULL, &child_reader, new);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't create thread.\n");
                return NULL;
        }

        pthread_detach(new->thread);
        
        return new;
}



/*
 *
 */
int server_process_requests(int client, void *clientdata) 
{
        manager_fd_set_t *set;
        
        
        /*
         * Hold the list lock until we add the connection.
         * Because adding a connection could have the side effect of modifying
         * the content of the list. (while a connection could be removed. Same
         * side effect).
         */
        pthread_mutex_lock(&list_mutex);
        
        if ( list_empty(&free_fd_list) ) {
                
                pthread_mutex_unlock(&list_mutex);
                
                set = create_fd_set();
                if ( ! set ) {
                        close(client);
                        return -1;
                }

                /*
                 * add_connection should never call
                 * list_del() at this time, so we don't need locking.
                 */
                add_connection(set, client, clientdata);
        } else {
                set = list_entry(free_fd_list.next, manager_fd_set_t, list);
                add_connection(set, client, clientdata);
                pthread_mutex_unlock(&list_mutex);
        }
        
        return 0;
}




void server_logic_init(int (*data_cb)(int fd, void *clientdata)) 
{
        data_available_cb = data_cb;
}
