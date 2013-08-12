#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_string.h>
#include "ngx_socks.h"
#include "ngx_socks_v5_module.h"

void ngx_socks_v5_handle_client_request(ngx_event_t *rev);
ngx_int_t ngx_socks_v5_request(ngx_event_t *rev);
static void ngx_socks_5_proxy_handler(ngx_event_t *rev);
static void ngx_socks_proxy_dummy_write(ngx_event_t *rev);
static void ngx_socks_proxy_block_read(ngx_event_t *rev);

static void ngx_socks_v5_resolve_addr_handler(ngx_resolver_ctx_t *ctx);
static void ngx_socks_v5_resolve_name(ngx_event_t *rev);
static void ngx_socks_v5_resolve_name_handler(ngx_resolver_ctx_t *ctx);
static void ngx_socks_v5_greeting(ngx_socks_session_t *s, ngx_connection_t *c);
static void ngx_socks_v5_invalid_pipelining(ngx_event_t *rev);
static ngx_int_t ngx_socks_v5_create_buffer(ngx_socks_session_t *s, ngx_connection_t *c);

static ngx_int_t ngx_socks_v5_helo(ngx_socks_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_socks_v5_auth(ngx_socks_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_socks_v5_mail(ngx_socks_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_socks_v5_starttls(ngx_socks_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_socks_v5_rset(ngx_socks_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_socks_v5_rcpt(ngx_socks_session_t *s, ngx_connection_t *c);

static ngx_int_t ngx_socks_v5_discard_command(ngx_socks_session_t *s, ngx_connection_t *c, char *err);
static void ngx_socks_v5_log_rejected_command(ngx_socks_session_t *s, ngx_connection_t *c, char *err);


static u_char smtp_ok[] = "250 2.0.0 OK" CRLF;
static u_char smtp_bye[] = "221 2.0.0 Bye" CRLF;
static u_char smtp_starttls[] = "220 2.0.0 Start TLS" CRLF;
static u_char smtp_next[] = "334 " CRLF;
static u_char smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
static u_char smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
static u_char smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
static u_char smtp_invalid_pipelining[] =
        "503 5.5.0 Improper use of SMTP command pipelining" CRLF;
static u_char smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
static u_char smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;
static u_char smtp_bad_sequence[] = "503 5.5.1 Bad sequence of commands" CRLF;


static ngx_str_t socks5_unavailable = ngx_string("[UNAVAILABLE]");
static ngx_str_t smtp_tempunavail = ngx_string("[TEMPUNAVAIL]");

void
ngx_socks_v5_init_session(ngx_socks_session_t *s, ngx_connection_t *c) {
    struct sockaddr_in *sin;
    ngx_resolver_ctx_t *ctx;
    ngx_socks_core_srv_conf_t *cscf;
    s->pool = ngx_create_pool(1024, c->log);

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    if (cscf->resolver == NULL) {
        s->host = socks5_unavailable;
        ngx_socks_v5_greeting(s, c);
        //wait for client send initial request for auth methods
        return;
    }

    if (c->sockaddr->sa_family != AF_INET) {
        s->host = smtp_tempunavail;
        ngx_socks_v5_greeting(s, c);
        return;
    }

    c->log->action = "in resolving client address";

    ctx = ngx_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        ngx_socks_close_connection(c);
        return;
    }

    /* AF_INET only */

    sin = (struct sockaddr_in *) c->sockaddr;

    ctx->addr = sin->sin_addr.s_addr;
    ctx->handler = ngx_socks_v5_resolve_addr_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    if (ngx_resolve_addr(ctx) != NGX_OK) {
        ngx_socks_close_connection(c);
    }
}

static void
ngx_socks_v5_resolve_addr_handler(ngx_resolver_ctx_t *ctx) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "%V could not be resolved (%i: %s)",
                &c->addr_text, ctx->state,
                ngx_resolver_strerror(ctx->state));

        if (ctx->state == NGX_RESOLVE_NXDOMAIN) {
            s->host = socks5_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

        ngx_resolve_addr_done(ctx);

        ngx_socks_v5_greeting(s, s->connection);

        return;
    }

    c->log->action = "in resolving client hostname";

    s->host.data = ngx_pstrdup(c->pool, &ctx->name);
    if (s->host.data == NULL) {
        ngx_resolve_addr_done(ctx);
        ngx_socks_close_connection(c);
        return;
    }

    s->host.len = ctx->name.len;

    ngx_resolve_addr_done(ctx);

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
            "address resolved: %V", &s->host);

    c->read->handler = ngx_socks_v5_resolve_name;

    ngx_post_event(c->read, &ngx_posted_events);
}

static void
ngx_socks_v5_resolve_name(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    ngx_resolver_ctx_t *ctx;
    ngx_socks_core_srv_conf_t *cscf;

    c = rev->data;
    s = c->data;

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    ctx = ngx_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        ngx_socks_close_connection(c);
        return;
    }

    ctx->name = s->host;
    ctx->type = NGX_RESOLVE_A;
    ctx->handler = ngx_socks_v5_resolve_name_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    if (ngx_resolve_name(ctx) != NGX_OK) {
        ngx_socks_close_connection(c);
    }
}

static void
ngx_socks_v5_resolve_name_handler(ngx_resolver_ctx_t *ctx) {
    in_addr_t addr;
    ngx_uint_t i;
    ngx_connection_t *c;
    struct sockaddr_in *sin;
    ngx_socks_session_t *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "\"%V\" could not be resolved (%i: %s)",
                &ctx->name, ctx->state,
                ngx_resolver_strerror(ctx->state));

        if (ctx->state == NGX_RESOLVE_NXDOMAIN) {
            s->host = socks5_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

    } else {

        /* AF_INET only */

        sin = (struct sockaddr_in *) c->sockaddr;

        for (i = 0; i < ctx->naddrs; i++) {

            addr = ctx->addrs[i];

            ngx_log_debug4(NGX_LOG_DEBUG_MAIL, c->log, 0,
                    "name was resolved to %ud.%ud.%ud.%ud",
                    (ntohl(addr) >> 24) & 0xff,
                    (ntohl(addr) >> 16) & 0xff,
                    (ntohl(addr) >> 8) & 0xff,
                    ntohl(addr) & 0xff);

            if (addr == sin->sin_addr.s_addr) {
                goto found;
            }
        }

        s->host = socks5_unavailable;
    }

found:

    ngx_resolve_name_done(ctx);

    ngx_socks_v5_greeting(s, c);
}

static void
ngx_socks_v5_greeting(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_msec_t timeout;
    ngx_socks_core_srv_conf_t *cscf;
    ngx_socks_v5_srv_conf_t *sscf;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
            "smtp greeting for \"%V\"", &s->host);

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

    timeout = sscf->greeting_delay ? sscf->greeting_delay : cscf->timeout;
    ngx_add_timer(c->read, timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_socks_close_connection(c);
    }

    if (sscf->greeting_delay) {
        c->read->handler = ngx_socks_v5_invalid_pipelining;
        return;
    }

    c->read->handler = ngx_socks_v5_init_protocol;

    s->out = sscf->greeting;

    ngx_socks_send(c->write);
}

static void
ngx_socks_v5_invalid_pipelining(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    ngx_socks_core_srv_conf_t *cscf;
    ngx_socks_v5_srv_conf_t *sscf;

    c = rev->data;
    s = c->data;

    c->log->action = "in delay pipelining state";

    if (rev->timedout) {

        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "delay greeting");

        rev->timedout = 0;

        cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

        c->read->handler = ngx_socks_v5_init_protocol;

        ngx_add_timer(c->read, cscf->timeout);

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_socks_close_connection(c);
            return;
        }

        sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

        s->out = sscf->greeting;

    } else {

        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "invalid pipelining");

        if (s->buffer == NULL) {
            if (ngx_socks_v5_create_buffer(s, c) != NGX_OK) {
                return;
            }
        }

        if (ngx_socks_v5_discard_command(s, c,
                "client was rejected before greeting: \"%V\"")
                != NGX_OK) {
            return;
        }

        ngx_str_set(&s->out, smtp_invalid_pipelining);
    }

    ngx_socks_send(c->write);
}

void
ngx_socks_v5_init_protocol(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_socks_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (ngx_socks_v5_create_buffer(s, c) != NGX_OK) {
            return;
        }
    }

    s->socks_state = ngx_smtp_start;
    c->read->handler = ngx_socks_v5_handle_client_request;
    s->protocol = NGX_SOCKS_V5;

    ngx_socks_v5_handle_client_request(rev);
}

static ngx_int_t
ngx_socks_v5_create_buffer(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_socks_v5_srv_conf_t *sscf;

    if (ngx_array_init(&s->args, c->pool, 2, sizeof (ngx_str_t)) == NGX_ERROR) {
        ngx_socks_session_internal_server_error(s);
        return NGX_ERROR;
    }

    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

    s->buffer = ngx_create_temp_buf(c->pool, sscf->client_buffer_size);
    if (s->buffer == NULL) {
        ngx_socks_session_internal_server_error(s);
        return NGX_ERROR;
    }

    return NGX_OK;
}
char* char2hex(char c, char* hex) {
    const char* hex_symbols = "0123456789ABCDEF";

    hex[0] = *(hex_symbols + ((c & 0xF0) >> 4));
    hex[1] = *(hex_symbols + (c & 0x0F));

    return hex;
}

static char supported_auth_methods[] = {
    0x00, /*'00' NO AUTHENTICATION REQUIRED*/
    0x01, /*'01' GSSAPI*/
    0x02, /*'02' USERNAME / PASSWORD */
    /*'03' to X'7F' IANA ASSIGNED
      '80' to X'FE' RESERVED FOR PRIVATE METHODS
     */
    0xFF /*'FF' NO ACCEPTABLE METHODS*/
};

ngx_int_t ngx_socks_v5_response_auth_methods(ngx_socks_session_t *s) {
    u_char nmethod;
    char hexMethod[2];

    //only the first two bytes
    if (s->buffer->last > s->buffer->pos) {
        if (*(s->buffer->pos) != 0x05) {
            return NGX_SOCKS_PARSE_INVALID_COMMAND;
        }
    }

    if (s->buffer->last - s->buffer->pos + 1 <= 2) {
        return NGX_AGAIN;
    }

    u_char nmethods = *(s->buffer->pos + 1);

    if (s->buffer->last - s->buffer->pos + 1 < 2 + nmethods) {
        return NGX_AGAIN;
    }

    //choose the auth methods in order: no auth, GSSAPI, USER/PWD
    for (nmethod = 0; nmethod < sizeof (supported_auth_methods); nmethod++) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "checking auth method: '%*s'", 2, char2hex(supported_auth_methods[nmethod], hexMethod));
        for (size_t method = 0; method < nmethods; method++) {
            if (*(s->buffer->pos + 2 + method) == supported_auth_methods[nmethod]) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "Found matched method at %uz: '%*s'", nmethod, 2, char2hex(supported_auth_methods[nmethod], hexMethod));
                s->auth_method = supported_auth_methods[nmethod];
                ngx_buf_t* buf = ngx_create_temp_buf(s->pool, sizeof(ngx_socks_auth_method_response_t));
                ngx_socks_auth_method_response_t* response = (ngx_socks_auth_method_response_t*)buf->pos;
                response->version = 5;
                response->method = s->auth_method;
                buf->last += sizeof (ngx_socks_auth_method_response_t); 
                
                ngx_chain_t *new_chain = ngx_alloc_chain_link(s->pool);
                new_chain->next = NULL;
                new_chain->buf = buf;
                
                ngx_chain_t* last_chain = s->out_chain;
                if(last_chain != NULL) {
                    while (last_chain->next != NULL) {
                        last_chain = last_chain->next;
                    }
                    
                    last_chain->next = new_chain;
                    last_chain->buf->last_in_chain = 0;
                } else {
                    s->out_chain = new_chain;
                }
                
                return NGX_DONE;
            }
        }
    }

    return NGX_OK;
}

void ngx_socks_v5_handle_client_request(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    c = rev->data;
    s = c->data;

    switch(s->socks_state){
        case ngx_socks_state_start:
            ngx_socks_v5_auth_state(rev);
            break;
        case ngx_socks_state_request:
            ngx_socks_v5_request(rev);
            break;
        default:
            break;
    }
}

ngx_int_t ngx_socks5_parse_addr(ngx_connection_t *connection, ngx_addr_t *addr, u_char *text, u_char address_type) {
    struct in_addr inaddr;
    ngx_uint_t family = 0;
    ngx_int_t rc;
    ngx_int_t len;
    struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
    struct in6_addr inaddr6;
    struct sockaddr_in6 *sin6;

    /*
     * prevent MSVC8 warning:
     *    potentially uninitialized local variable 'inaddr6' used
     */
    ngx_memzero(&inaddr6, sizeof (struct in6_addr));
#endif

    u_char* dest_address;
    ngx_int_t port_offset;
    
    switch (address_type) {
        case 0x01:
            family = AF_INET;
            inaddr = *(struct in_addr*) (text);
            dest_address = ngx_pcalloc(connection->pool, INET_ADDRSTRLEN);
            char* converted = inet_ntop(family, &inaddr, (char*)dest_address, INET_ADDRSTRLEN);
            if(converted == NULL){
                ngx_log_error(NGX_LOG_ERR, connection->log, 0, "could not convert, errno: %d", errno);    
            }
            len = sizeof(struct sockaddr_in);
            port_offset = 4;
            ngx_log_error(NGX_LOG_ERR, connection->log, 0, "requested ip: %*s", strlen(dest_address), dest_address);
            rc = NGX_OK;
            break;
        case 0x03:
            break;
        case 0x04:
            break;
    }

    addr->sockaddr = ngx_pcalloc(connection->pool, len);
    if (addr->sockaddr == NULL) {
        return NGX_ERROR;
    }

    addr->sockaddr->sa_family = (u_char) family;
    addr->name.len = strlen((char*)dest_address);
    addr->name.data = dest_address;
    
    addr->socklen = len;

    switch (family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) addr->sockaddr;
            ngx_memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) addr->sockaddr;
            sin->sin_port = *(text + port_offset) << 8 | *(text + port_offset + 1);
            sin->sin_addr = inaddr;
            
            break;
    }

    return NGX_OK;
}

static u_char *server_host = "localhost";

ngx_chain_t* ngx_socks_alloc_chain(ngx_socks_buf_chain_t *chains) {
    return NULL;
}

ngx_int_t ngx_socks_v5_request(ngx_event_t *rev) {
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "socks request state");

    rc = ngx_socks_read_command(s, c);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return rc;
    }

    if (s->buffer->last - s->buffer->pos + 1 <= 8) {
        return NGX_AGAIN;
    }

    if(*(s->buffer->pos) != 0x05) {
        return NGX_SOCKS_PARSE_INVALID_COMMAND;
    }

    ngx_int_t expected_request_len = 7;
    u_char address_type = *(s->buffer->pos + 3);
    switch (address_type) {
        case 0x01:
            expected_request_len +=4;
            break;
        case 0x03:
            expected_request_len += *(s->buffer->pos + 4) + 1;
            break;
        case 0x04:
            expected_request_len += 16;
            break;
        default:
            return NGX_SOCKS_PARSE_INVALID_COMMAND;
    }

    if (s->buffer->last - s->buffer->pos + 1 < expected_request_len) {
        return NGX_AGAIN;
    }

    ngx_addr_t *peer = ngx_pcalloc(s->connection->pool, sizeof (ngx_addr_t));
    if (peer == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "could not alloc memory for peer address");
        ngx_socks_session_internal_server_error(s);
        return NGX_ERROR;
    }
    
    rc = ngx_socks5_parse_addr(s->connection, peer, s->buffer->pos + 4, address_type);
    switch (rc) {
        case NGX_OK:
            break;

        case NGX_DECLINED:
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "auth http server sent invalid server "
                    "address");
            /* fall through */
        default:
            ngx_socks_session_internal_server_error(s);
            return NGX_ERROR;
    }

    ngx_socks_proxy_ctx_t *proxy_context = ngx_palloc(s->connection->pool, sizeof(*proxy_context));
    if(proxy_context == NULL) {
        ngx_socks_session_internal_server_error(s);
        return NGX_ERROR;
    }
    proxy_context->upstream.data = s;
    s->proxy = proxy_context;
    
    proxy_context->upstream.sockaddr = peer->sockaddr;
    proxy_context->upstream.socklen = peer->socklen;
    proxy_context->upstream.name = &peer->name;
    proxy_context->upstream.get = ngx_event_get_peer;
    proxy_context->upstream.log = s->connection->log;
    proxy_context->upstream.log_error = NGX_ERROR_ERR;
    
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "requesting url: %V:%ud ", &peer->name, ((struct sockaddr_in*)peer->sockaddr)->sin_port);
    
    rc = ngx_event_connect_peer(&proxy_context->upstream);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_socks_session_internal_server_error(s);
        return NGX_ERROR;
    }
    
    proxy_context->upstream.connection->write->handler = ngx_socks_proxy_dummy_write;
    
    ngx_socks_core_srv_conf_t *cscf;

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    ngx_add_timer(proxy_context->upstream.connection->read, cscf->timeout);

    proxy_context->upstream.connection->data = s;
    proxy_context->upstream.connection->pool = s->connection->pool;

//    s->connection->read->handler = ngx_socks_proxy_block_read;
    proxy_context->upstream.connection->write->handler = ngx_socks_proxy_dummy_write;

//    pcf = ngx_socks_get_module_srv_conf(s, ngx_socks_proxy_module);
    //should get buffer size from configuration file
    s->proxy->buffer = ngx_create_temp_buf(s->connection->pool, 16 * 1024);
    if (s->proxy->buffer == NULL) {
        ngx_socks_session_internal_server_error(s);
        return NGX_ERROR;
    }

    s->out.len = 0;
    
    //send the new ip and port for request
    int response_addr_len = strlen(server_host);
    
    ngx_buf_t* buf = ngx_create_temp_buf(s->pool, sizeof (ngx_socks_request_response_t) + response_addr_len + 1);
    ngx_socks_request_response_t* response = (ngx_socks_request_response_t*) buf->pos;
    response->version = 0x05;
    response->response_code = 0x00;
    response->reserved = 0x00;
    response->address_type = 0x03;
    *response->bind_address = response_addr_len;
    ngx_memcpy(response->bind_address + 1, server_host, response_addr_len);
    *(response->bind_address + response_addr_len + 1) = (u_char)(9999 >> 8);
    *(response->bind_address + response_addr_len + 2) = (u_char)(9999 &0xFF);
    
    buf->last += sizeof (ngx_socks_request_response_t) + response_addr_len;

    ngx_chain_t *new_chain = ngx_alloc_chain_link(s->pool);
    new_chain->next = NULL;
    new_chain->buf = buf;

    ngx_chain_t* last_chain = s->out_chain;
    if (last_chain != NULL) {
        while (last_chain->next != NULL) {
            last_chain = last_chain->next;
        }
        
        last_chain->next = new_chain;
        last_chain->buf->last_in_chain = 0;
    } else {
        s->out_chain = new_chain;
    }
    
//    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    if (s->state) {
        s->arg_start = s->buffer->start;
    }

    ngx_socks_send(c->write);
}

static void ngx_socks_5_proxy_handler(ngx_event_t *rev) {

}

static void ngx_socks_proxy_block_read(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_mail_session_t *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "socks block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_socks_close_connection(s);
    }
}

static void
ngx_socks_proxy_dummy_write(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_mail_session_t *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "socks block write");

    if (ngx_handle_write_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_socks_close_connection(s);
    }
}

void
ngx_socks_v5_auth_state(ngx_event_t *rev) {
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "socks auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_socks_close_connection(c);
        return;
    }

    if (s->out_chain != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "socks send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_socks_read_command(s, c);

    if (rc == NGX_AGAIN || rc == NGX_ERROR ) {
        return;
    }

    int next_state;
    switch(s->auth_state) {
        case ngx_socks_auth_start:
            rc = ngx_socks_v5_response_auth_methods(s);
            break;
        default:
            break;
    }
    
    if (rc == NGX_AGAIN || rc == NGX_ERROR || rc == NGX_SOCKS_PARSE_INVALID_COMMAND) {
        return;
    }

    switch (rc) {

        case NGX_ERROR:
            ngx_socks_session_internal_server_error(s);
            return;

        case NGX_SOCKS_PARSE_INVALID_COMMAND:
            /* TODO: close connection */

        case NGX_DONE:
            s->socks_state = ngx_socks_state_request;
            // continue NGX_OK to write to client, 
        case NGX_OK:
            s->args.nelts = 0;
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;

            if (s->state) {
                s->arg_start = s->buffer->start;
            }

            ngx_socks_send(c->write);
    }
}

static ngx_int_t
ngx_socks_v5_helo(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_str_t *arg;
    ngx_socks_v5_srv_conf_t *sscf;

    if (s->args.nelts != 1) {
        ngx_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return NGX_OK;
    }

    arg = s->args.elts;

    s->smtp_helo.len = arg[0].len;

    s->smtp_helo.data = ngx_pnalloc(c->pool, arg[0].len);
    if (s->smtp_helo.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);

    ngx_str_null(&s->smtp_from);
    ngx_str_null(&s->smtp_to);

    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

    if (s->command == NGX_SMTP_HELO) {
        s->out = sscf->server_name;

    } else {
        s->esmtp = 1;

#if (NGX_MAIL_SSL)

        if (c->ssl == NULL) {
            ngx_socks_ssl_conf_t *sslcf;

            sslcf = ngx_socks_get_module_srv_conf(s, ngx_socks_ssl_module);

            if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
                s->out = sscf->starttls_capability;
                return NGX_OK;
            }

            if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
                s->out = sscf->starttls_only_capability;
                return NGX_OK;
            }
        }
#endif

        s->out = sscf->capability;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_socks_v5_auth(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_int_t rc;
    ngx_socks_core_srv_conf_t *cscf;
    ngx_socks_v5_srv_conf_t *sscf;

#if (NGX_MAIL_SSL)
    if (ngx_socks_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts == 0) {
        ngx_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return NGX_OK;
    }

    rc = ngx_socks_auth_parse(s, c);

    switch (rc) {

        case NGX_MAIL_AUTH_LOGIN:

            ngx_str_set(&s->out, smtp_username);
            s->socks_state = ngx_smtp_auth_login_username;

            return NGX_OK;

        case NGX_MAIL_AUTH_LOGIN_USERNAME:

            ngx_str_set(&s->out, smtp_password);
            s->socks_state = ngx_smtp_auth_login_password;

            return ngx_socks_auth_login_username(s, c, 1);

        case NGX_MAIL_AUTH_PLAIN:

            ngx_str_set(&s->out, smtp_next);
            s->socks_state = ngx_smtp_auth_plain;

            return NGX_OK;

        case NGX_MAIL_AUTH_CRAM_MD5:

            sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

            if (!(sscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            }

            if (s->salt.data == NULL) {
                cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

                if (ngx_socks_salt(s, c, cscf) != NGX_OK) {
                    return NGX_ERROR;
                }
            }

            if (ngx_socks_auth_cram_md5_salt(s, c, "334 ", 4) == NGX_OK) {
                s->socks_state = ngx_smtp_auth_cram_md5;
                return NGX_OK;
            }

            return NGX_ERROR;
    }

    return rc;
}

static ngx_int_t
ngx_socks_v5_mail(ngx_socks_session_t *s, ngx_connection_t *c) {
    u_char ch;
    ngx_str_t l;
    ngx_uint_t i;
    ngx_socks_v5_srv_conf_t *sscf;

    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

    if (!(sscf->auth_methods & NGX_MAIL_AUTH_NONE_ENABLED)) {
        ngx_socks_v5_log_rejected_command(s, c, "client was rejected: \"%V\"");
        ngx_str_set(&s->out, smtp_auth_required);
        return NGX_OK;
    }

    /* auth none */

    if (s->smtp_from.len) {
        ngx_str_set(&s->out, smtp_bad_sequence);
        return NGX_OK;
    }

    l.len = s->buffer->last - s->buffer->start;
    l.data = s->buffer->start;

    for (i = 0; i < l.len; i++) {
        ch = l.data[i];

        if (ch != CR && ch != LF) {
            continue;
        }

        l.data[i] = ' ';
    }

    while (i) {
        if (l.data[i - 1] != ' ') {
            break;
        }

        i--;
    }

    l.len = i;

    s->smtp_from.len = l.len;

    s->smtp_from.data = ngx_pnalloc(c->pool, l.len);
    if (s->smtp_from.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->smtp_from.data, l.data, l.len);

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
            "smtp mail from:\"%V\"", &s->smtp_from);

    ngx_str_set(&s->out, smtp_ok);

    return NGX_OK;
}

static ngx_int_t
ngx_socks_v5_rcpt(ngx_socks_session_t *s, ngx_connection_t *c) {
    u_char ch;
    ngx_str_t l;
    ngx_uint_t i;

    if (s->smtp_from.len == 0) {
        ngx_str_set(&s->out, smtp_bad_sequence);
        return NGX_OK;
    }

    l.len = s->buffer->last - s->buffer->start;
    l.data = s->buffer->start;

    for (i = 0; i < l.len; i++) {
        ch = l.data[i];

        if (ch != CR && ch != LF) {
            continue;
        }

        l.data[i] = ' ';
    }

    while (i) {
        if (l.data[i - 1] != ' ') {
            break;
        }

        i--;
    }

    l.len = i;

    s->smtp_to.len = l.len;

    s->smtp_to.data = ngx_pnalloc(c->pool, l.len);
    if (s->smtp_to.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->smtp_to.data, l.data, l.len);

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
            "smtp rcpt to:\"%V\"", &s->smtp_to);

    s->auth_method = NGX_MAIL_AUTH_NONE;

    return NGX_DONE;
}

static ngx_int_t
ngx_socks_v5_rset(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_str_null(&s->smtp_from);
    ngx_str_null(&s->smtp_to);
    ngx_str_set(&s->out, smtp_ok);

    return NGX_OK;
}

static ngx_int_t
ngx_socks_v5_starttls(ngx_socks_session_t *s, ngx_connection_t *c) {
#if (NGX_MAIL_SSL)
    ngx_socks_ssl_conf_t *sslcf;

    if (c->ssl == NULL) {
        sslcf = ngx_socks_get_module_srv_conf(s, ngx_socks_ssl_module);
        if (sslcf->starttls) {

            /*
             * RFC3207 requires us to discard any knowledge
             * obtained from client before STARTTLS.
             */

            ngx_str_null(&s->smtp_helo);
            ngx_str_null(&s->smtp_from);
            ngx_str_null(&s->smtp_to);

            c->read->handler = ngx_socks_starttls_handler;
            return NGX_OK;
        }
    }

#endif

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}

static ngx_int_t
ngx_socks_v5_discard_command(ngx_socks_session_t *s, ngx_connection_t *c,
        char *err) {
    ssize_t n;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == NGX_ERROR || n == 0) {
        ngx_socks_close_connection(c);
        return NGX_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_socks_session_internal_server_error(s);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    ngx_socks_v5_log_rejected_command(s, c, err);

    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    return NGX_OK;
}

static void
ngx_socks_v5_log_rejected_command(ngx_socks_session_t *s, ngx_connection_t *c,
        char *err) {
    u_char ch;
    ngx_str_t cmd;
    ngx_uint_t i;

    if (c->log->log_level < NGX_LOG_INFO) {
        return;
    }

    cmd.len = s->buffer->last - s->buffer->start;
    cmd.data = s->buffer->start;

    for (i = 0; i < cmd.len; i++) {
        ch = cmd.data[i];

        if (ch != CR && ch != LF) {
            continue;
        }

        cmd.data[i] = '_';
    }

    cmd.len = i;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, err, &cmd);
}
