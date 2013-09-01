#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_socks.h"
#include "ngx_socks_v5_module.h"

static void *ngx_socks_v5_create_srv_conf(ngx_conf_t *cf);
static char *ngx_socks_v5_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_socks_protocol_t ngx_socks_v5_protocol = {
    ngx_string("socks5"), 
    { 0x53, 0x4B, 0x43, 0x4F, 0x53, 0x35, 0},
    NGX_SOCKS_V5,

    ngx_socks_v5_init_session,
};

static ngx_command_t ngx_socks_v5_commands[] = {

    { ngx_string("v5_client_buffer"),
        NGX_SOCKS_MAIN_CONF | NGX_SOCKS_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_SOCKS_SRV_CONF_OFFSET,
        offsetof(ngx_socks_v5_srv_conf_t, client_buffer_size),
        NULL},

    ngx_null_command
};


static ngx_socks_module_t ngx_socks_v5_module_ctx = {
    &ngx_socks_v5_protocol, /* protocol */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_socks_v5_create_srv_conf, /* create server configuration */
    ngx_socks_v5_merge_srv_conf /* merge server configuration */
};


ngx_module_t ngx_socks_v5_module = {
    NGX_MODULE_V1,
    &ngx_socks_v5_module_ctx, /* module context */
    ngx_socks_v5_commands, /* module directives */
    NGX_SOCKS_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_socks_v5_create_srv_conf(ngx_conf_t *cf) {
    ngx_socks_v5_srv_conf_t *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof (ngx_socks_v5_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    sscf->client_buffer_size = NGX_CONF_UNSET_SIZE;

    return sscf;
}

static char *
ngx_socks_v5_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_socks_v5_srv_conf_t *prev = parent;
    ngx_socks_v5_srv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->client_buffer_size,
            prev->client_buffer_size,
            (size_t) ngx_pagesize);

    return NGX_CONF_OK;
}
