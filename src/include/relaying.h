int manager_parent_tell_alive(prelude_client_t *client);

int manager_parent_tell_dead(prelude_client_t *client);

int manager_children_tell_dead(prelude_client_t *client);

int manager_parent_add_client(prelude_client_t *client);

prelude_client_t *manager_parent_search_client(const char *addr, int type);

void manager_relay_msg_if_needed(prelude_msg_t *msg);

int manager_parent_setup_from_cfgline(const char *cfgline);

int manager_children_setup_from_cfgline(const char *cfgline);

void manager_relay_init(void);


