int sensor_server_start(const char *addr, uint16_t port);

int sensor_server_broadcast_admin_command(const char *sensorid, prelude_msg_t *msg);
