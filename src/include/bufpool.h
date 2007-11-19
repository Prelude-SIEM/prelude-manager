typedef struct bufpool bufpool_t;


void bufpool_destroy(bufpool_t *bp);

int bufpool_new(bufpool_t **bp, const char *filename);

size_t bufpool_get_message_count(bufpool_t *bp);

int bufpool_get_message(bufpool_t *bp, prelude_msg_t **msg);

int bufpool_add_message(bufpool_t *bp, prelude_msg_t *msg);

void bufpool_set_disk_threshold(size_t threshold);

void bufpool_print_stats(void);
