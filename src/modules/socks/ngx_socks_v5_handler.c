#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_string.h>
#include "ngx_socks.h"
#include "ngx_socks_v5_module.h"

void ngx_socks_v5_handle_client_request(ngx_event_t *rev);
ngx_int_t ngx_socks_v5_request(ngx_event_t *rev);
static void ngx_socks_proxy_block_read(ngx_event_t *rev);
static void ngx_socks_proxy_connected(ngx_event_t *rev);
static ngx_int_t ngx_socks_v5_connect_requested_host(ngx_socks_session_t *s, ngx_connection_t *c, ngx_addr_t *peer);
static void ngx_socks_v5_resolve_name(ngx_socks_session_t *s, ngx_connection_t *c, ngx_str_t *name);
static void ngx_socks_v5_resolve_name_handler(ngx_resolver_ctx_t *ctx);
static ngx_int_t ngx_socks_v5_create_buffer(ngx_socks_session_t *s, ngx_connection_t *c, ngx_buf_t **buf, char* buf_type);
static void ngx_socks_v5_pass_through(ngx_event_t *rev);
static u_char *ngx_pstrdup_n(ngx_pool_t *pool, u_char *src, ngx_int_t size);
static ngx_int_t ngx_socks_v5_connect_upstream(ngx_socks_session_t *s, ngx_connection_t *c, ngx_int_t family, void* address, short port);

void ngx_socks_v5_init_session(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_msec_t timeout;
    ngx_socks_core_srv_conf_t *cscf;
    ngx_socks_v5_srv_conf_t *sscf;

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "socks connected from client");

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

    timeout = sscf->greeting_delay ? sscf->greeting_delay : cscf->timeout;
    ngx_add_timer(c->read, timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_socks_proxy_close_session(s);
    }

    c->read->handler = ngx_socks_v5_init_protocol;
}

static void ngx_socks_v5_resolve_name(ngx_socks_session_t *s, ngx_connection_t *c, ngx_str_t *name) {
    ngx_resolver_ctx_t *ctx, temp;
    ngx_socks_core_srv_conf_t *cscf;

    temp.name = *name;
    
    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
    ctx = ngx_resolve_start(cscf->resolver, &temp);
    if (ctx == NULL) {
        ngx_socks_proxy_close_session(s);
        return;
    }

    ctx->name.data = name->data;
    ctx->name.len = name->len;
    ctx->type = NGX_RESOLVE_A;
    ctx->handler = ngx_socks_v5_resolve_name_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;
    
    if (ngx_resolve_name(ctx) != NGX_OK) {
        ngx_socks_proxy_close_session(s);
    }
    s->resolver_ctx = ctx;
}

static void
ngx_socks_v5_resolve_name_handler(ngx_resolver_ctx_t *ctx) {
    in_addr_t addr;
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    
    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "\"%V\" could not be resolved (%i: %s)",
                &s->host, ctx->state,
                ngx_resolver_strerror(ctx->state));
        ngx_socks_proxy_close_session(s);
    } else {
        /* AF_INET only */
        if (ctx->naddrs > 0) {
            addr = ctx->addrs[0];
            ngx_log_debug5(NGX_LOG_DEBUG_SOCKS, c->log, 0, 
                    "name '%V' was resolved to %ud.%ud.%ud.%ud",
                    &s->host,
                    (ntohl(addr) >> 24) & 0xff,
                    (ntohl(addr) >> 16) & 0xff,
                    (ntohl(addr) >> 8) & 0xff,
                    ntohl(addr) & 0xff);
        }

        ngx_socks_v5_connect_upstream(s, c, AF_INET, (struct in_addr*) &addr, s->port);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_SOCKS, c->log, 0, "socks resolve name done in handler session: %p, ctx: %p", s, ctx);
    ngx_resolve_name_done(ctx);
    s->resolver_ctx = NULL;
}

void
ngx_socks_v5_init_protocol(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    c = rev->data;
    s = c->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_socks_proxy_close_session(s);
        return;
    }

    if(ngx_socks_v5_create_buffer(s, c, &s->buffer, "client request") != NGX_OK) {
        return;
    }
    
    if(ngx_socks_v5_create_buffer(s, c, &s->out_buffer, "client response") != NGX_OK) {
        return;
    }
    
    s->socks_state = ngx_socks_state_start;
    c->read->handler = ngx_socks_v5_handle_client_request;
    s->protocol = NGX_SOCKS_V5;

    ngx_socks_v5_handle_client_request(rev);
}

static ngx_int_t ngx_socks_v5_create_buffer(ngx_socks_session_t *s, ngx_connection_t *c, ngx_buf_t **buf, char* buf_type) {
    ngx_socks_v5_srv_conf_t *sscf;

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "create buffer for %s", buf_type);
    
    if(*buf == NULL) {
        sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

        *buf = ngx_create_temp_buf(c->pool, sscf->client_buffer_size);
        
        if(*buf == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "Could not create buffer for %s", buf_type);
            ngx_socks_session_internal_server_error(s);
            
            return NGX_ERROR;
        }
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
    ngx_connection_t *c;
    
    char hexMethod[2];

    if (s->buffer->last - s->buffer->pos + 1 <= 2) {
        return NGX_AGAIN;
    }

    if (*(s->buffer->pos) != 0x05) {
        return NGX_SOCKS_PARSE_INVALID_COMMAND;
    }

    u_char nmethods = *(s->buffer->pos + 1);

    if (s->buffer->last - s->buffer->pos + 1 < 2 + nmethods) {
        return NGX_AGAIN;
    }

    c = s->connection;
    
    //choose the auth methods in order: no auth, USER/PWD
    for (nmethod = 0; nmethod < sizeof (supported_auth_methods); nmethod++) {
        ngx_log_debug2(NGX_LOG_DEBUG_SOCKS, c->log, 0, "checking auth method: '%*s'", 2, char2hex(supported_auth_methods[nmethod], hexMethod));
        
        for (size_t method = 0; method < nmethods; method++) {
            if (*(s->buffer->pos + 2 + method) == supported_auth_methods[nmethod]) {
                ngx_log_debug2(NGX_LOG_DEBUG_SOCKS, c->log, 0, "Using auth method: '%*s'", 2, char2hex(supported_auth_methods[nmethod], hexMethod));
                
                s->auth_method = supported_auth_methods[nmethod];
                
                ngx_socks_auth_method_response_t* response = (ngx_socks_auth_method_response_t*)s->out_buffer->pos;
                response->version = 0x05;
                response->method = s->auth_method;
                
                s->out_buffer->last += sizeof (ngx_socks_auth_method_response_t); 
                
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
        case ngx_socks_state_wait_request:
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

static u_char *server_host = (u_char*)"localhost";

static void ngx_socks_v5_pass_through(ngx_event_t *rev) {
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

    ngx_log_debug(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0,
            "Started transfer data between upstream and client");

    while(true) {
        if (do_write) {
            size = buf->last - buf->pos;
            if(size && target->write->ready) {
                c->log->action=send_action;
                
                sent_n = target->send(target, buf->pos, size);
                
                if(sent_n == NGX_ERROR) {
                    ngx_log_debug(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0,
                            "Failed to send data, closing connections");
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
                    ngx_log_debug(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0,
                            "Failed to recv data, closing connections");

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
        ngx_log_debug(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0,
                "Finished transfer data, closing connections");

        ngx_socks_proxy_close_session(s);
    }
}

static ngx_int_t ngx_socks_v5_connect_upstream(ngx_socks_session_t *s, ngx_connection_t *c, ngx_int_t family, void* address, short port) {
    ngx_int_t rc;
    struct in_addr inaddr;
    ngx_int_t len;
    ngx_int_t ip_address_len;
    struct sockaddr_in *sin;

    u_char* dest_address;

#if (NGX_HAVE_INET6)
    struct in6_addr inaddr6;
    struct sockaddr_in6 *sin6;
    /*
     * prevent MSVC8 warning:
     *    potentially uninitialized local variable 'inaddr6' used
     */
    ngx_memzero(&inaddr6, sizeof (struct in6_addr));
#endif

    ngx_addr_t *peer = ngx_pcalloc(s->connection->pool, sizeof (ngx_addr_t));
    if (peer == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "could not allocate memory for peer address");
        ngx_socks_session_internal_server_error(s);
        return NGX_ERROR;
    }

    switch (family) {
        case AF_INET: //IPv4
            inaddr = *(struct in_addr*) address;
            
            dest_address = ngx_pcalloc(c->pool, INET_ADDRSTRLEN);
            const char* converted = inet_ntop(family, &inaddr, (char*) dest_address, INET_ADDRSTRLEN);
            if (converted == NULL) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "could not convert, errno: %d", errno);
            }
            ip_address_len = strlen(converted);
            s->host.data = ngx_pstrdup_n(c->pool, dest_address, ip_address_len);
            s->host.len = ip_address_len;

            len = sizeof (struct sockaddr_in);
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "requested ip: %V", &s->host);
            rc = NGX_OK;
            break;
        default: //IPv6
            break;
    }

    peer->sockaddr = ngx_pcalloc(c->pool, len);
    if (peer->sockaddr == NULL) {
        return NGX_ERROR;
    }

    peer->sockaddr->sa_family = (u_char) family;
    peer->name.len = strlen((char*) dest_address);
    peer->name.data = dest_address;

    peer->socklen = len;

    switch (family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) peer->sockaddr;
            ngx_memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) peer->sockaddr;
            sin->sin_port = port;
            sin->sin_addr.s_addr = inaddr.s_addr;

            break;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "Could not parse IPV4 address.");
        ngx_socks_session_internal_server_error(s);
        return rc;
    }

    return ngx_socks_v5_connect_requested_host(s, c, peer);    
}

static ngx_int_t ngx_socks_v5_connect_requested_host(ngx_socks_session_t *s, ngx_connection_t *c, ngx_addr_t *peer) {
    ngx_int_t rc;    

    ngx_socks_proxy_ctx_t *proxy_context = ngx_pcalloc(s->connection->pool, sizeof (*proxy_context));
    if (proxy_context == NULL) {
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

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "requesting url: %V:%ud ", &peer->name, ntohs(((struct sockaddr_in*) peer->sockaddr)->sin_port));

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
    
    return NGX_OK;
}

static u_char *ngx_pstrdup_n(ngx_pool_t *pool, u_char *src, ngx_int_t size) {
    u_char *dst;

    dst = ngx_pnalloc(pool, size);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src, size);

    return dst;
}

ngx_int_t ngx_socks_v5_request(ngx_event_t *rev) {
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "socks: received client request");

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
    ngx_int_t port_offset;
    u_char address_type = *(s->buffer->pos + 3);
    switch (address_type) {
        case 0x01:
            expected_request_len +=4;
            port_offset = 4 + 4;
            break;
        case 0x03:
            expected_request_len += *(s->buffer->pos + 4) + 1;
            port_offset = 4 + *(s->buffer->pos + 4) + 1;
            break;
        case 0x04:
            expected_request_len += 16;
            port_offset = 4 + 16;
            break;
        default:
            return NGX_SOCKS_PARSE_INVALID_COMMAND;
    }

    if (s->buffer->last - s->buffer->pos + 1 < expected_request_len) {
        return NGX_AGAIN;
    }

    s->port = *(short*) (s->buffer->pos + port_offset); //already network order
    
    switch (address_type) {
        case 0x01:
            return ngx_socks_v5_connect_upstream(s, c, AF_INET, (struct in_addr*) (s->buffer->pos + 4), *(short*)(s->buffer->pos + port_offset));
        case 0x03:
            s->host.data = ngx_pstrdup_n(c->pool, s->buffer->pos + 5, *(s->buffer->pos + 4));
            if (s->host.data == NULL) {
                ngx_socks_proxy_close_session(s);
                return NGX_ERROR;
            }

            s->host.len = *(s->buffer->pos + 4);

            ngx_socks_v5_resolve_name(s, c, &s->host);
            return NGX_OK;
        default:
            return NGX_OK;
            
    }
}

static void ngx_socks_proxy_block_read(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, rev->log, 0, "socks block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_log_debug(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0,
        "Failed in socks_proxy_block_read, closing connections");

        ngx_socks_proxy_close_session(s);
    }
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

static void ngx_socks_del_timer(ngx_socks_session_t *s, ngx_event_t *ev, char *message) {
    if(ev->timer_set) {
        ngx_del_timer(ev);
        ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0, message);
    }
}

static void ngx_socks_proxy_connected(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, rev->log, 0, "socks check if upstream has been connected");

    c = rev->data;
    s = c->data;
    
    if (ngx_http_upstream_test_connect(c) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, rev->log, 0, "socks upstream has not been connected, will try again later");
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, rev->log, 0, "socks upstream connected, start to send response to client");

    //send the new ip and port for request
    int response_addr_len = strlen((char*)server_host);

    ngx_socks_request_response_t* response = (ngx_socks_request_response_t*) s->out_buffer->pos;
    response->version = 0x05;
    response->response_code = 0x00;
    response->reserved = 0x00;
    response->address_type = 0x03;
    *response->bind_address = response_addr_len;
    ngx_memcpy(response->bind_address + 1, server_host, response_addr_len);

    //    ngx_socket_t port = proxy_context->upstream.local->fd;

    *(response->bind_address + response_addr_len + 1) = (u_char) (9999 >> 8);
    *(response->bind_address + response_addr_len + 2) = (u_char) (9999 & 0xFF);

    s->out_buffer->last += sizeof (ngx_socks_request_response_t) + response_addr_len + 3;

    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    ngx_socks_send(s->connection->write);

    if (ngx_socks_v5_create_buffer(s, c, &s->upstream_buffer, "upstream response") != NGX_OK) {
        return;
    }

    s->proxy->upstream.connection->read->handler = ngx_socks_v5_pass_through;
    s->proxy->upstream.connection->write->handler = ngx_socks_v5_pass_through;
    ngx_del_timer(s->proxy->upstream.connection->read);
    
    ngx_socks_del_timer(s, s->connection->read, "Delete client read timer");
    ngx_socks_del_timer(s, s->connection->write, "Delete client write timer");
    ngx_socks_del_timer(s, s->proxy->upstream.connection->read, "Delete upstream read timer");
    ngx_socks_del_timer(s, s->proxy->upstream.connection->write, "Delete upstream write timer");

    s->socks_state = ngx_socks_state_pass_through;
}

void ngx_socks_v5_auth_state(ngx_event_t *rev) {
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "socks auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_socks_proxy_close_session(s);
        return;
    }

    if (s->out_buffer->last - s->out_buffer->pos > 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "socks send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_socks_read_command(s, c);

    if (rc != NGX_OK ) {
        return;
    }

    switch(s->auth_state) {
        case ngx_socks_auth_start:
            rc = ngx_socks_v5_response_auth_methods(s);
            break;
        default:
            break;
    }

    switch (rc) {
        case NGX_ERROR:
            ngx_socks_session_internal_server_error(s);
            return;

        case NGX_SOCKS_PARSE_INVALID_COMMAND:
            /* TODO: close connection */
            ngx_socks_proxy_close_session(s);
            return;
        case NGX_DONE:
            s->socks_state = ngx_socks_state_wait_request;
            // continue NGX_OK to write to client, 
        case NGX_OK:
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;

            ngx_socks_send(c->write);
    }
}
