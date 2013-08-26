#ifndef NGX_SOCKS_V5_MODULE_H
#define	NGX_SOCKS_V5_MODULE_H

#ifdef	__cplusplus
extern "C" {
#endif


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_mail.h"

typedef struct {
    size_t client_buffer_size;
} ngx_socks_v5_srv_conf_t;

void ngx_socks_v5_init_session(ngx_socks_session_t *s, ngx_connection_t *c);
void ngx_socks_v5_init_protocol(ngx_event_t *rev);
void ngx_socks_v5_auth_state(ngx_event_t *rev);
ngx_int_t ngx_socks_v5_parse_command(ngx_socks_session_t *s);

extern ngx_module_t ngx_socks_v5_module;

#ifdef	__cplusplus
}
#endif

#endif	/* NGX_SOCKS_V5_MODULE_H */

