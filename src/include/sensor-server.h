void sensor_server_start(void);

int sensor_server_new(const char *addr, uint16_t port);

int sensor_server_broadcast_admin_command(const char *sensorid, prelude_msg_t *msg);
