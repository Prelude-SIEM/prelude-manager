#include <stdio.h>
#include <netinet/in.h>

#include <libprelude/idmef.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/idmef-message-read.h>

#include "idmef-util.h"
#include "plugin-decode.h"
#include "pmsg-to-idmef.h"



static int handle_heartbeat_msg(prelude_msg_t *msg, idmef_message_t *idmef)
{
        idmef_heartbeat_t *heartbeat;
        
        heartbeat = idmef_message_new_heartbeat(idmef);
        if ( ! heartbeat )
                return -1;

        if ( ! idmef_read_heartbeat(msg, heartbeat) )
                return -1;

        manager_idmef_heartbeat_get_ident(heartbeat);

        return 0;
}




static int handle_alert_msg(prelude_msg_t *msg, idmef_message_t *idmef)
{
        idmef_alert_t *alert;
                        
        alert = idmef_message_new_alert(idmef);
        if ( ! alert )
                return -1;
        
        if ( ! idmef_read_alert(msg, alert) )
                return -1;
        
        manager_idmef_alert_get_ident(alert);

        return 0;
}




static int handle_proprietary_msg(prelude_msg_t *msg, idmef_message_t *idmef, void *buf, uint32_t len)
{
        int ret;
        uint8_t tag;
        
        ret = extract_uint8_safe(&tag, buf, len);
        if ( ret < 0 )
                return -1;
                        
        ret = decode_plugins_run(tag, msg, idmef);
        if ( ret < 0 )
                return -1;

        return 0;
}



idmef_message_t *pmsg_to_idmef(prelude_msg_t *msg) 
{
	int ret;
	void *buf;
	uint8_t tag;
	uint32_t len;
        idmef_message_t *idmef;
        
	idmef = idmef_message_new();
	if ( ! idmef ) {
		log(LOG_ERR, "memory exhausted.\n");
		return NULL;
	}

        while ( (ret = prelude_msg_get(msg, &tag, &len, &buf)) > 0 ) {
                
                if ( tag == MSG_ALERT_TAG ) 
			ret = handle_alert_msg(msg, idmef);

                else if ( tag == MSG_HEARTBEAT_TAG ) 
                        ret = handle_heartbeat_msg(msg, idmef);

                else if ( tag == MSG_OWN_FORMAT )
                        ret = handle_proprietary_msg(msg, idmef, buf, len);

                else log(LOG_ERR, "unknow tag: %d.\n", tag);
                
                if ( ret < 0 )
                        break;
        }
        
        if ( ret == 0 )
                return idmef;

        log(LOG_ERR, "error reading IDMEF message.\n");
        idmef_message_destroy(idmef);
                
        return NULL;
}
