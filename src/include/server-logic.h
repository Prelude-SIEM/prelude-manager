void server_logic_init(int (*data_cb)(int fd, void *clientdata));

int server_process_requests(int client, void *clientdata);
