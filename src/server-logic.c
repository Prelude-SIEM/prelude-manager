#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <pthread.h>
#include <assert.h>

#include <libprelude/list.h>
#include <libprelude/common.h>

#include "server-logic.h"


#define MAX_FD_BY_PROCESS 100
#define DEBUG

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
        
        pthread_mutex_t pfd_mutex;

        struct pollfd used_tbl[MAX_FD_BY_PROCESS];

        int free_index;
        struct pollfd *free_tbl[MAX_FD_BY_PROCESS];
        
} manager_fd_set_t;

        

/*
 * This list contain pointer to set that have available space.
 */
static LIST_HEAD(free_fd_list);
static pthread_mutex_t list_mutex;
static int (*data_available_cb)(int fd);



static void remove_connection(manager_fd_set_t *set, struct pollfd *pfd) 
{
        int ret;

        /*
         * Close the file descriptor associated with this set.
         * Handle the case where close could be interrupted.
         */
        do {
                ret = close(pfd->fd);
        } while ( ret < 0 && errno == EINTR );

        assert(ret >= 0);       

        /*
         * From The Single UNIX Specification, Version 2 :
         *
         * If the value of fd is less than 0,
         * events is ignored and revents is set to 0 in that entry on return from poll().
         */
        pfd->fd = -1;

        
        /*
         * Lock the list before locking the thread mutex,
         * to prevent a race with a connection on the way to be added
         * (list already locked and this set obtained from the list,
         * then add_connection() waiting on this set mutex while we are killing
         * the set because there is no more FD used.
         */
        pthread_mutex_lock(&list_mutex);
        pthread_mutex_lock(&set->pfd_mutex);
        
        /*
         * Increase the number of free fd,
         * then add this fd to our free fd array.
         */
        set->free_tbl[set->free_index++] = pfd;

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
        else if ( set->free_index == MAX_FD_BY_PROCESS ) {
                
                list_del(&set->list);
                
                pthread_mutex_unlock(&set->pfd_mutex);
                pthread_mutex_unlock(&list_mutex);
                
                pthread_mutex_destroy(&set->pfd_mutex);

                free(set);

                dprint("Killing thread %ld\n", pthread_self());
                pthread_exit(NULL);
        }
        
        pthread_mutex_unlock(&set->pfd_mutex);
        pthread_mutex_unlock(&list_mutex);
}



static void add_connection(manager_fd_set_t *set, int fd) 
{
        struct pollfd *ptr;
        
        pthread_mutex_lock(&set->pfd_mutex);
        
        /*
         * We should never enter here if there is no free fd.
         */
        assert(set->free_index > 0);

        /*
         * Get a free fd.
         */
        ptr = set->free_tbl[--set->free_index];
        
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
        
        pthread_mutex_unlock(&set->pfd_mutex);
        
        assert(ptr->fd == -1);
        
        /*
         * Setup monitoring for this file descriptor.
         */
        ptr->fd = fd;
        ptr->events = POLLIN;
}




static int handle_fd_event(manager_fd_set_t *set, struct pollfd *pfd) 
{        
        /*
         * Data is available on this fd,
         * call the user provided callback.
         */        
        if ( pfd->revents & POLLIN ) {
                
                if ( data_available_cb(pfd->fd) < 0 )
                        remove_connection(set, pfd);

                return 0;
        }

        /*
         * Error or hangup occured. 
         */
        else {
                dprint("thread=%ld - Hanging up.\n", pthread_self());
                remove_connection(set, pfd);
                return 0;
        }

        return -1;
}





static void *child_reader(void *ptr) 
{
        int i, ret, active_fd;
        manager_fd_set_t *set = ptr;
        struct pollfd fdset[MAX_FD_BY_PROCESS];
        
        while ( 1 ) {
                /*
                 * Is there a way to avoid this copy ?
                 */
                pthread_mutex_lock(&set->pfd_mutex);
                memcpy(fdset, set->used_tbl, sizeof(fdset));
                pthread_mutex_unlock(&set->pfd_mutex);
                
                /*
                 * Use a one second timeout,
                 * in order to take new FD for this set into account.
                 */
                active_fd = poll(fdset, MAX_FD_BY_PROCESS, 1000);                
                if ( active_fd < 0 ) {
                        if ( errno == EINTR ) 
                                continue;
                        
                        log(LOG_ERR, "Error polling FDs set.\n");
                }

                else if ( active_fd == 0 ) 
                        continue; /* timeout */
                
                for ( i = 0; i < MAX_FD_BY_PROCESS && active_fd > 0; i++ ) {
                        /*
                         * This fd is ignored (-1).
                         */
                        if ( fdset[i].fd < 0 )
                                continue;

                        set->used_tbl[i].revents = fdset[i].revents;
                        
                        ret = handle_fd_event(set, &set->used_tbl[i]);
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

        new->free_index = MAX_FD_BY_PROCESS;
        
        for ( i = 0; i < MAX_FD_BY_PROCESS; i++ ) {
                new->used_tbl[i].fd = -1;
                new->free_tbl[i] = &new->used_tbl[i];
        }

        pthread_mutex_init(&new->pfd_mutex, NULL);
        
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
int server_process_requests(int client) 
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
                add_connection(set, client);
        } else {
                set = list_entry(free_fd_list.next, manager_fd_set_t, list);
                add_connection(set, client);
                pthread_mutex_unlock(&list_mutex);
        }
        
        return 0;
}




void server_logic_init(int (*data_cb)(int fd)) 
{
        data_available_cb = data_cb;
}
