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
static ngx_int_t ngx_socks_proxy_connected(ngx_event_t *rev);

static void ngx_socks_v5_resolve_addr_handler(ngx_resolver_ctx_t *ctx);
static void ngx_socks_v5_resolve_name(ngx_event_t *rev);
static void ngx_socks_v5_resolve_name_handler(ngx_resolver_ctx_t *ctx);
static void ngx_socks_v5_greeting(ngx_socks_session_t *s, ngx_connection_t *c);
static ngx_buf_t* ngx_socks_v5_create_buffer(ngx_socks_session_t *s, ngx_connection_t *c);
static void ngx_socks_v5_pass_through(ngx_event_t *rev);

static ngx_str_t socks5_unavailable = ngx_string("[UNAVAILABLE]");
static ngx_str_t socks5_tempunavail = ngx_string("[TEMPUNAVAIL]");

void
ngx_socks_v5_init_session(ngx_socks_session_t *s, ngx_connection_t *c) {
    struct sockaddr_in *sin;
    ngx_resolver_ctx_t *ctx;
    ngx_socks_core_srv_conf_t *cscf;
    s->pool = ngx_create_pool(1024, c->log);

//    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

//    if (cscf->resolver == NULL) {
        s->host = socks5_unavailable;
        ngx_socks_v5_greeting(s, c);
        //wait for client send initial request for auth methods
        return;
//    }
//
//    if (c->sockaddr->sa_family != AF_INET) {
//        s->host = socks5_tempunavail;
//        ngx_socks_v5_greeting(s, c);
//        return;
//    }
//
//    c->log->action = "in resolving client address";
//
//    ctx = ngx_resolve_start(cscf->resolver, NULL);
//    if (ctx == NULL) {
//        ngx_socks_close_connection(c);
//        return;
//    }
//
//    /* AF_INET only */
//
//    sin = (struct sockaddr_in *) c->sockaddr;
//
//    ctx->addr = sin->sin_addr.s_addr;
//    ctx->handler = ngx_socks_v5_resolve_addr_handler;
//    ctx->data = s;
//    ctx->timeout = cscf->resolver_timeout;
//
//    if (ngx_resolve_addr(ctx) != NGX_OK) {
//        ngx_socks_close_connection(c);
//    }
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
            s->host = socks5_tempunavail;
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
            s->host = socks5_tempunavail;
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

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0, "socks greeting for \"%V\"", &s->host);

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

    timeout = sscf->greeting_delay ? sscf->greeting_delay : cscf->timeout;
    ngx_add_timer(c->read, timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_socks_close_connection(c);
    }

    c->read->handler = ngx_socks_v5_init_protocol;
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
        s->buffer = ngx_socks_v5_create_buffer(s, c);
        
        if (s->buffer == NULL) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "Could not create buffer for request");
            ngx_socks_session_internal_server_error(s);
            return;
        }
    }

    s->socks_state = ngx_socks_state_start;
    c->read->handler = ngx_socks_v5_handle_client_request;
    s->protocol = NGX_SOCKS_V5;

    ngx_socks_v5_handle_client_request(rev);
}

static ngx_buf_t*
ngx_socks_v5_create_buffer(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_socks_v5_srv_conf_t *sscf;

    if (ngx_array_init(&s->args, c->pool, 2, sizeof (ngx_str_t)) == NGX_ERROR) {
        ngx_socks_session_internal_server_error(s);
        return NULL;
    }

    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

    return ngx_create_temp_buf(c->pool, sscf->client_buffer_size);
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
                
                ngx_chain_t *new_chain = ngx_socks_alloc_chain(&s->out_buf_chain);
                new_chain->buf = buf;
                
                ngx_chain_t* last_chain = s->out_buf_chain.chains;
                if(last_chain != NULL) {
                    while (last_chain->next != NULL) {
                        last_chain = last_chain->next;
                    }
                    
                    last_chain->next = new_chain;
                    last_chain->buf->last_in_chain = 0;
                } else {
                    s->out_buf_chain.chains = new_chain;
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
        case ngx_socks_state_pass_through:
            ngx_socks_v5_pass_through(rev);
            break;
        default:
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "::::---(((((( UNKNOWN state: %uz", s->socks_state);
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
            const char* converted = inet_ntop(family, &inaddr, (char*)dest_address, INET_ADDRSTRLEN);
            if(converted == NULL){
                ngx_log_error(NGX_LOG_ERR, connection->log, 0, "could not convert, errno: %d", errno);    
            }
            len = sizeof(struct sockaddr_in);
            port_offset = 4;
            ngx_log_error(NGX_LOG_ERR, connection->log, 0, "requested ip: %*s", strlen((char*) dest_address), dest_address);
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
            sin->sin_port = *(short*)(text+port_offset);//already network order
            sin->sin_addr.s_addr = inaddr.s_addr;
            
            break;
    }

    return NGX_OK;
}

static u_char *server_host = (u_char*)"localhost";

ngx_chain_t* ngx_socks_alloc_chain(ngx_socks_buf_chains_t *chains) {
    ngx_chain_t *new_chain = NULL;
    if(chains->free_chains != NULL) {
        new_chain = chains->free_chains;
        chains->free_chains = new_chain->next;
    } else {
        new_chain = ngx_alloc_chain_link(chains->pool);    
    }
    
    new_chain->next = NULL;
    new_chain->buf = NULL;
    
    return new_chain;
}

void ngx_socks_free_buf_chain(ngx_socks_buf_chains_t *chains, ngx_chain_t *chain) {
    ngx_chain_t *current_chain = chains->chains;
    
    if(current_chain != chain) {
        return;
    }
    
    chains->chains= current_chain->next;
    current_chain->next = chains->free_chains;
    chains->free_chains = current_chain;
}

static void ngx_socks_proxy_close_session(ngx_socks_session_t *s) {
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "close socks proxy connection: %d",
                s->proxy->upstream.connection->fd);

        ngx_close_connection(s->proxy->upstream.connection);
    }

    ngx_socks_close_connection(s->connection);
}

static void ngx_socks_v5_pass_through(ngx_event_t *rev) {
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    char *send_action, *recv_action;
    ngx_connection_t *source, *target;
    ngx_buf_t *buf;
    bool do_write;
    ssize_t size, sent_n;
    
    c = rev->data;
    s = c->data;
    //do nothing if it's read request, pass through data to the other side
    
    if(c == s->connection) {
        //event from client side
        if(rev->write) {
            source = s->proxy->upstream.connection;
            target = s->connection;
            buf = s->buffer;
            
            recv_action = "proxying and read from upstream";
            send_action = "proxying and sending to client";
        }else{
            source = s->connection;
            target = s->proxy->upstream.connection; 
            buf = s->upstream_buffer;

            recv_action = "proxying and read from client";
            send_action = "proxying and sending to upstream";
        }
    }else{
        //event from upstream side
        if(rev->write){
            source = s->connection;
            target = s->proxy->upstream.connection;      
            buf = s->upstream_buffer;
            
            recv_action = "proxying and read from client";
            send_action = "proxying and sending to upstream";
        }else{
            source = s->proxy->upstream.connection;
            target = s->connection;
            buf = s->buffer;

            recv_action = "proxying and read from upstream";
            send_action = "proxying and sending to client";
        }
    }
    
    do_write = rev->write ? true : false;

    while(true) {
        if (do_write) {
            size = buf->last - buf->pos;
            if(size && target->write->ready) {
                c->log->action=send_action;
                
                sent_n = target->send(target, buf->pos, size);
                
                if(sent_n == NGX_ERROR) {
                    ngx_socks_proxy_close_session(s);
                    return;
                }
                
                if(sent_n > 0) {
                    buf->pos += sent_n;
                    
                    if(buf->pos == buf->last) {
                        buf->pos = buf->start;
                        buf->last = buf->start;
                    }else{
                        continue;
                    }
                }
            }
        } else {
            size = buf->end - buf->last;
            if (size && source->read->ready) {
                c->log->action = recv_action;

                sent_n = source->recv(source, buf->last, size);

                if (sent_n == NGX_ERROR) {
                    ngx_socks_proxy_close_session(s);
                    return;
                }

                if (sent_n == NGX_AGAIN || sent_n == 0) {
                    break;
                }
                
                if (sent_n > 0) {
                    buf->last += sent_n;
                    do_write = true;
                    if (rev->pending_eof) {
                        source->read->eof = 1;
                    }
                    continue;
                }
                
            }
        }
        break;
    }
    if((s->connection->read->eof && s->buffer->pos == s->buffer->last) ||
            (s->proxy->upstream.connection->read->eof && s->upstream_buffer->pos == s->upstream_buffer->last) ||
            (s->connection->read->eof && s->proxy->upstream.connection->read->eof)
            ) {
        ngx_socks_proxy_close_session(s);
    }
//    
//    if(ngx_handle_write_event(target->write, 0) != NGX_OK) {
//        ngx_socks_proxy_close_session(s);
//        return;
//    }
//    
//    if(ngx_handle_read_event(target->read, 0) != NGX_OK) {
//        ngx_socks_proxy_close_session(s);
//        return;
//    }
//    
//    if(ngx_handle_write_event(target->write, 0) != NGX_OK) {
//        ngx_socks_proxy_close_session(s);
//        return;
//    }
//    
//    if(ngx_handle_read_event(target->read, 0) != NGX_OK) {
//        ngx_socks_proxy_close_session(s);
//        return;
//    }
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
    
    proxy_context->upstream.connection->read->handler = ngx_socks_proxy_block_read;
    proxy_context->upstream.connection->write->handler = ngx_socks_proxy_connected;
    
    ngx_socks_core_srv_conf_t *cscf;

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    ngx_add_timer(proxy_context->upstream.connection->read, cscf->timeout);

    proxy_context->upstream.connection->data = s;
    proxy_context->upstream.connection->pool = s->connection->pool;

//    s->connection->read->handler = ngx_socks_proxy_block_read;

//    pcf = ngx_socks_get_module_srv_conf(s, ngx_socks_proxy_module);
    //should get buffer size from configuration file
//    s->proxy->buffer = ngx_create_temp_buf(s->connection->pool, 16 * 1024);
//    if (s->proxy->buffer == NULL) {
//        ngx_socks_session_internal_server_error(s);
//        return NGX_ERROR;
//    }

}

static void ngx_socks_5_proxy_handler(ngx_event_t *rev) {

}

static void ngx_socks_proxy_block_read(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "socks block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_socks_proxy_close_session(s);
    }
}

static void ngx_socks_proxy_do_request(ngx_event_t *rev) {
    
}

static void
ngx_socks_proxy_dummy_write(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "socks block write");

    if (ngx_handle_write_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_socks_proxy_close_session(s);
    }
    
    c->write->handler = ngx_socks_proxy_do_request;
}

static ngx_int_t
ngx_http_upstream_test_connect(ngx_connection_t *c) {
    int err;
    socklen_t len = sizeof (int);

    /*
     * BSDs and Linux return 0 and set a pending error in err
     * Solaris returns -1 and sets errno
     */
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
        err = ngx_errno;

        c->log->action = "connecting to upstream";
        (void) ngx_connection_error(c, err, "connect() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_socks_proxy_connected(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "socks check connected");

    c = rev->data;
    s = c->data;
    
    if (ngx_http_upstream_test_connect(c) != NGX_OK) {
        return NGX_AGAIN;
    }

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

    //    ngx_socket_t port = proxy_context->upstream.local->fd;

    *(response->bind_address + response_addr_len + 1) = (u_char) (9999 >> 8);
    *(response->bind_address + response_addr_len + 2) = (u_char) (9999 & 0xFF);

    buf->last += sizeof (ngx_socks_request_response_t) + response_addr_len + 3;

    ngx_chain_t *new_chain = ngx_socks_alloc_chain(&s->out_buf_chain);
    new_chain->buf = buf;

    ngx_chain_t* last_chain = s->out_buf_chain.chains;
    if (last_chain != NULL) {
        while (last_chain->next != NULL) {
            last_chain = last_chain->next;
        }

        last_chain->next = new_chain;
        last_chain->buf->last_in_chain = 0;
    } else {
        s->out_buf_chain.chains = new_chain;
    }

    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    ngx_socks_send(s->connection->write);


    if (s->upstream_buffer == NULL) {
        s->upstream_buffer = ngx_socks_v5_create_buffer(s, c);

        if (s->upstream_buffer == NULL) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "Could not create buffer for upstream response");
            ngx_socks_session_internal_server_error(s);
            return NGX_ERROR;
        }
    }

    s->proxy->upstream.connection->read->handler = ngx_socks_v5_pass_through;
    s->proxy->upstream.connection->write->handler = ngx_socks_v5_pass_through;
    s->socks_state = ngx_socks_state_pass_through;
    return NGX_OK;
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

    if (s->out_buf_chain.chains != NULL) {
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
