#ifndef NGX_SOCKS_H
#define	NGX_SOCKS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
    void **main_conf;
    void **srv_conf;
} ngx_socks_conf_ctx_t;

typedef struct {
    int family;
    in_port_t port;
    ngx_array_t addrs; /* array of ngx_mail_conf_addr_t */
} ngx_socks_conf_port_t;

typedef struct {
    u_char sockaddr[NGX_SOCKADDRLEN];
    socklen_t socklen;

    /* server ctx */
    ngx_socks_conf_ctx_t *ctx;

    unsigned bind : 1;
    unsigned wildcard : 1;
#if (NGX_SOCKS_SSL)
    unsigned ssl : 1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned ipv6only : 1;
#endif
    unsigned so_keepalive : 2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int tcp_keepidle;
    int tcp_keepintvl;
    int tcp_keepcnt;
#endif
} ngx_socks_listen_t;
    
typedef struct {
    ngx_socks_conf_ctx_t *ctx;
    ngx_str_t addr_text;
#if (NGX_MAIL_SSL)
    ngx_uint_t ssl; /* unsigned   ssl:1; */
#endif
} ngx_socks_addr_conf_t;

typedef struct {
    in_addr_t addr;
    ngx_socks_addr_conf_t conf;
} ngx_socks_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr addr6;
    ngx_socks_addr_conf_t conf;
} ngx_socks_in6_addr_t;

#endif

typedef struct {
    /* ngx_socks_in_addr_t or ngx_socks_in6_addr_t */
    void *addrs;
    ngx_uint_t naddrs;
} ngx_socks_port_t;

typedef struct {
    struct sockaddr *sockaddr;
    socklen_t socklen;

    ngx_socks_conf_ctx_t *ctx;

    unsigned bind : 1;
    unsigned wildcard : 1;
#if (NGX_SOCKS_SSL)
    unsigned ssl : 1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned ipv6only : 1;
#endif
    unsigned so_keepalive : 2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int tcp_keepidle;
    int tcp_keepintvl;
    int tcp_keepcnt;
#endif
} ngx_socks_conf_addr_t;


typedef struct ngx_socks_protocol_s ngx_socks_protocol_t;

typedef struct {
    ngx_socks_protocol_t *protocol;

    void *(*create_main_conf)(ngx_conf_t *cf);
    char *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void *(*create_srv_conf)(ngx_conf_t *cf);
    char *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_socks_module_t;

typedef struct {
    ngx_array_t servers; /* ngx_socks_core_srv_conf_t */
    ngx_array_t listen; /* ngx_socks_listen_t */
} ngx_socks_core_main_conf_t;

typedef struct {
    ngx_socks_protocol_t *protocol;

    ngx_msec_t timeout;
    ngx_msec_t resolver_timeout;

    ngx_flag_t so_keepalive;

    ngx_str_t server_name;

    u_char *file_name;
    ngx_int_t line;

    ngx_resolver_t *resolver;

    /* server ctx */
    ngx_socks_conf_ctx_t *ctx;
} ngx_socks_core_srv_conf_t;

typedef enum {
    ngx_socks_state_start = 0,
    ngx_socks_state_auth_login_username,
    ngx_socks_state_auth_login_password,
    ngx_socks_state_auth_plain,
    ngx_socks_state_wait_request,
    ngx_socks_state_resolve_requested_host,
    ngx_socks_state_resolved_requested_host,
    ngx_socks_state_connecting_requested_host,
    ngx_socks_state_pass_through
} ngx_socks_state_e;
    
typedef enum {
    ngx_socks_auth_start=0,
    ngx_socks_auth_password=1,
} ngx_socks_auth_state_e;

typedef enum {
    ipv4 = 0x01,
    hostname = 0x03,
    ipv6 = 0x04            
} ngx_socks_address_type_e;

typedef struct {
    u_char version;
    u_char method;
} ngx_socks_auth_method_response_t;

typedef struct {
    u_char version;
    u_char response_code;
    u_char reserved;
    u_char address_type;
    u_char bind_address[];
} ngx_socks_request_response_t;

typedef struct {
    ngx_peer_connection_t upstream;
    ngx_buf_t *buffer;
} ngx_socks_proxy_ctx_t;

typedef struct {
    ngx_chain_t *chains;
    ngx_chain_t *free_chains;
    ngx_pool_t *pool;
} ngx_socks_buf_chains_t;

typedef struct {
    ngx_connection_t *connection;

    ngx_socks_buf_chains_t in_buf_chain;
    ngx_socks_buf_chains_t out_buf_chain;
    
    ngx_buf_t *buffer;
    ngx_buf_t *out_buffer;
    ngx_buf_t *upstream_buffer;

    void **ctx;
    void **main_conf;
    void **srv_conf;
    ngx_pool_t *pool;

    ngx_resolver_ctx_t *resolver_ctx;

    ngx_socks_proxy_ctx_t *proxy;

    ngx_uint_t socks_state;
    ngx_uint_t auth_state;

    unsigned protocol : 3;
    unsigned blocked : 1;
    unsigned quit : 1;
    unsigned starttls : 1;
    
    unsigned auth_wait : 1;

    u_char auth_method;
    ngx_str_t login;
    ngx_str_t passwd;

    ngx_str_t *addr_text;
    ngx_str_t host;

    ngx_uint_t login_attempt;

    unsigned short port;
} ngx_socks_session_t;

typedef struct {
    ngx_str_t *client;
    ngx_socks_session_t *session;
} ngx_socks_log_ctx_t;


typedef void (*ngx_socks_init_session_pt)(ngx_socks_session_t *s,
        ngx_connection_t *c);

struct ngx_socks_protocol_s {
    ngx_str_t name;
    in_port_t port[7];
    ngx_uint_t type;

    ngx_socks_init_session_pt init_session;

    ngx_str_t internal_server_error;
};


#define NGX_SOCKS_MODULE         0x534B434F53     /* "SOCKS" */

#define NGX_SOCKS_MAIN_CONF      0x02000000
#define NGX_SOCKS_SRV_CONF       0x04000000

#define NGX_SOCKS_V4      0
#define NGX_SOCKS_V5      1

#define NGX_SOCKS_PARSE_INVALID_COMMAND  20

#define NGX_SOCKS_MAIN_CONF_OFFSET  offsetof(ngx_socks_conf_ctx_t, main_conf)
#define NGX_SOCKS_SRV_CONF_OFFSET   offsetof(ngx_socks_conf_ctx_t, srv_conf)


#define ngx_socks_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_socks_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_socks_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_socks_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_socks_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_socks_conf_get_module_main_conf(cf, module)                       \
    ((ngx_socks_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_socks_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_socks_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


extern ngx_uint_t ngx_socks_max_module;
extern ngx_module_t ngx_socks_core_module;

void ngx_socks_close_connection(ngx_connection_t *c);
u_char* ngx_socks_log_error(ngx_log_t *log, u_char *buf, size_t len);
void ngx_socks_session_internal_server_error(ngx_socks_session_t *s);
void ngx_socks_proxy_close_session(ngx_socks_session_t *s);
void ngx_socks_send(ngx_event_t *wev);

void ngx_socks_init_connection(ngx_connection_t *c);
ngx_int_t ngx_socks_read_command(ngx_socks_session_t *s, ngx_connection_t *c);

#ifdef	__cplusplus
}
#endif

#endif	/* NGX_SOCKS_H */

