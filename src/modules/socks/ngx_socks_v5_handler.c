#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_string.h>
#include "ngx_socks.h"
#include "ngx_socks_v5_module.h"

void ngx_socks_v5_handle_client_request(ngx_event_t *rev);
static void ngx_socks_v5_auth(ngx_event_t *rev);
static void ngx_socks_v5_request(ngx_event_t *rev);
static void ngx_socks_v5_pass_through(ngx_event_t *rev);

static u_char *ngx_pstrdup_n(ngx_pool_t *pool, u_char *src, ngx_int_t size);
static ngx_int_t ngx_socks_v5_create_buffer(ngx_socks_session_t *s, ngx_connection_t *c, ngx_buf_t **buf, char* buf_type);

static void ngx_socks_v5_resolve_name(ngx_socks_session_t *s, ngx_connection_t *c, u_char *name, size_t len);
static void ngx_socks_v5_resolve_name_handler(ngx_resolver_ctx_t *ctx);

static ngx_int_t ngx_socks_v5_connect_upstream(ngx_socks_session_t *s, ngx_connection_t *c, ngx_int_t family, void* address, short port);
static ngx_int_t ngx_socks_v5_connect_requested_host(ngx_socks_session_t *s, ngx_connection_t *c, ngx_addr_t *peer);
static void ngx_socks_proxy_connected(ngx_event_t *rev);
static void ngx_socks_proxy_block_read(ngx_event_t *rev);

static ngx_socks_auth_method_response_t no_auth = {0x05, 0x00};
static ngx_socks_auth_method_response_t no_supported_methods = {0x05, 0xFF};

static ngx_socks_request_response_t request_response_head = {0x05, 0x00, 0x00, 0x03};

void 
ngx_socks_v5_init_session(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_msec_t timeout;
    ngx_socks_core_srv_conf_t *cscf;
    ngx_socks_v5_srv_conf_t *sscf;

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "socks connected from client");

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);
    
    //TODO: start to init ssl if sscf->ssl is on, and use sscf->ssl_timeout for client read timeout.
    
    timeout = cscf->timeout;
    ngx_add_timer(c->read, timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_socks_proxy_close_session(s);
        return;
    }

    s->socks_state = ngx_socks_state_start;
    c->read->handler = ngx_socks_v5_handle_client_request;
}

static ngx_int_t ngx_socks_v5_create_buffer(ngx_socks_session_t *s, ngx_connection_t *c, ngx_buf_t **buf, char* buf_type) {
    ngx_socks_v5_srv_conf_t *sscf;

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "create buffer for %s", buf_type);

    sscf = ngx_socks_get_module_srv_conf(s, ngx_socks_v5_module);

    *buf = ngx_create_temp_buf(c->pool, sscf->client_buffer_size);

    if (*buf == NULL) {
        ngx_socks_server_error(s, NGX_ENOMEM, "Could not create buffer for %s", buf_type);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void ngx_socks_v5_resolve_name(ngx_socks_session_t *s, ngx_connection_t *c, u_char *name, size_t len) {
    ngx_resolver_ctx_t *ctx, temp;
    ngx_socks_core_srv_conf_t *cscf;

    s->host.len = len;
    s->host.data = ngx_pstrdup_n(c->pool, name, len);
    if (s->host.data == NULL) {
        ngx_socks_server_error(s, NGX_ENOMEM, "Could not alloc memory for upstream address: %*s", len, name);
        return;
    }
    
    temp.name = s->host;
    
    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
    ctx = ngx_resolve_start(cscf->resolver, &temp);
    if (ctx == NULL || ctx == NGX_NO_RESOLVER) {
        ngx_socks_server_error(s, NGX_ENOMEM, "Could not start resolver for upstream: '%V'", s->host);
        return;
    }

    ctx->name = s->host;
    ctx->type = NGX_RESOLVE_A;
    ctx->handler = ngx_socks_v5_resolve_name_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;
    s->resolver_ctx = ctx;
    
    if (ngx_resolve_name(ctx) != NGX_OK) {
        s->resolver_ctx = NULL;
        ngx_socks_server_error(s, 0, "Could not resolve name for upstream: '%V'", s->host);
    }    
}

static void
ngx_socks_v5_resolve_name_handler(ngx_resolver_ctx_t *ctx) {
    in_addr_t addr;
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    
    s = ctx->data;
    c = s->connection;

    if (ctx->state || ctx->naddrs <= 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "\"%V\" could not be resolved (%i: %s)",
                &s->host, ctx->state, ngx_resolver_strerror(ctx->state));
        ngx_resolve_name_done(ctx);
        s->resolver_ctx = NULL;
        ngx_socks_proxy_close_session(s);
    } else {
        /* AF_INET only */
        addr = ctx->addrs[0];
        ngx_log_debug5(NGX_LOG_DEBUG_SOCKS, c->log, 0, 
                "name '%V' was resolved to %ud.%ud.%ud.%ud",
                &s->host,
                (ntohl(addr) >> 24) & 0xff,
                (ntohl(addr) >> 16) & 0xff,
                (ntohl(addr) >> 8) & 0xff,
                ntohl(addr) & 0xff);

        ngx_resolve_name_done(ctx);
        s->resolver_ctx = NULL;

        ngx_socks_v5_connect_upstream(s, c, AF_INET, (struct in_addr*) &addr, s->port);
    }
}

void ngx_socks_reset_buffer(ngx_buf_t *buf) {
    buf->pos = buf->start;
    buf->last = buf->start;
}

void
ngx_socks_send_response(ngx_connection_t *c, ngx_buf_t *buf, void* ptr, size_t size) {
    ngx_memcpy(buf->pos, ptr, size);
    buf->last += size;
    
    ngx_socks_send(c->write);
}

static void 
ngx_socks_v5_auth(ngx_event_t *rev) {
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    size_t buf_len;

    c = rev->data;
    s = c->data;

    c->log->action = "in auth state";

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "SOCKS: Start to read command");

    rc = ngx_socks_read_command(s, c);

    if (rc != NGX_OK) {
        return;
    }

    buf_len = s->buffer->last - s->buffer->pos + 1;
    
    //05 01 00
    if (buf_len < 3) {
        return;
    }

    if (*(s->buffer->pos) != 0x05) {
        ngx_socks_bad_request(s, 0, "Received unknown request, the first byte is not 0x05");
        return;
    }

    u_char nmethods = *(s->buffer->pos + 1);

    if (buf_len < 2 + nmethods) {
        return;
    }

    //The only supported auth method: no auth
    for (size_t method = 0; method < nmethods; method++) {
        if (*(s->buffer->pos + 2 + method) == 0x00) {
            ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "Using auth method: '0x00'");

            s->socks_state = ngx_socks_state_wait_request;
            
            ngx_socks_reset_buffer(s->buffer);
            ngx_socks_send_response(c, s->out_buffer, &no_auth, sizeof(no_auth));
            
            return;
        }
    }

    //return no supported auth method, and then close the connection.
    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "No supported auth method found, mark the connection to be quit");
    
    s->quit = 1;
    ngx_socks_send_response(c, s->out_buffer, &no_supported_methods, sizeof(no_supported_methods));
    
    return;
}

void 
ngx_socks_v5_handle_client_request(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_socks_proxy_close_session(s);
        return;
    }
    
    switch(s->socks_state){
        case ngx_socks_state_start:
            c->log->action = "in init state";

            if (ngx_socks_v5_create_buffer(s, c, &s->buffer, "client request") != NGX_OK ||
                ngx_socks_v5_create_buffer(s, c, &s->out_buffer, "client response") != NGX_OK) {
                return;
            }
            
            s->socks_state = ngx_socks_state_auth;
            //pass through to auth state
        case ngx_socks_state_auth:
            ngx_socks_v5_auth(rev);

            s->protocol = NGX_SOCKS_V5;

            break;
        case ngx_socks_state_wait_request:
            ngx_socks_v5_request(rev);
            break;
        case ngx_socks_state_pass_through:
            ngx_socks_v5_pass_through(rev);
            break;
        default:
            ngx_socks_server_error(s, 0, "Illegal connection state: %uz", s->socks_state);
            break;
    }
}

static u_char *server_host = (u_char*)"localhost";

static void 
ngx_socks_v5_pass_through(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    char *send_action, *recv_action;
    ngx_connection_t *source, *target;
    ngx_buf_t *buf;
    bool do_write;
    ssize_t size, sent_n;
    
    c = rev->data;
    s = c->data;
    
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

                if (sent_n > 0) {
                    buf->pos += sent_n;

                    if (buf->pos == buf->last) {
                        ngx_socks_reset_buffer(buf);
                    } else {
                        continue;
                    }
                }

                if(sent_n == NGX_ERROR) {
                    ngx_socks_server_error(s, 0, "Failed to send data, closing connections");
                    return;
                }                
            }
        } else {
            size = buf->end - buf->last;
            if (size && source->read->ready) {
                c->log->action = recv_action;

                sent_n = source->recv(source, buf->last, size);

                if (sent_n > 0) {
                    buf->last += sent_n;
                    do_write = true;
                    if (rev->pending_eof) {
                        source->read->eof = 1;
                    }
                    continue;
                }
                
                if (sent_n == NGX_ERROR) {
                    ngx_socks_server_error(s, 0, "Failed to recv data, closing connections");
                    return;
                }

                if (sent_n == NGX_AGAIN || sent_n == 0) {
                    break;
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

static ngx_int_t 
ngx_socks_v5_connect_upstream(ngx_socks_session_t *s, ngx_connection_t *c, ngx_int_t family, void* address, short port) {
    struct in_addr inaddr;
    ngx_int_t len;
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

    ngx_addr_t *peer = ngx_pcalloc(c->pool, sizeof (ngx_addr_t));
    if (peer == NULL) {
        ngx_socks_server_error(s, NGX_ENOMEM, "could not allocate memory for peer address");
        return NGX_ERROR;
    }

    switch (family) {
        case AF_INET: //IPv4
            inaddr = *(struct in_addr*) address;
            
            dest_address = ngx_pcalloc(c->pool, INET_ADDRSTRLEN);
            if (dest_address == NULL) {
                ngx_socks_server_error(s, NGX_ENOMEM, "could not allocate memory for dest address");
                return NGX_ERROR;
            }

            const char* converted = inet_ntop(family, &inaddr, (char*) dest_address, INET_ADDRSTRLEN);
            if (converted == NULL) {
                ngx_socks_server_error(s, 0, "could not convert, errno: %d", errno);
                return NGX_ERROR;
            }
            
            s->host.len = strlen(converted);
            s->host.data = ngx_pstrdup_n(c->pool, dest_address, s->host.len);
            if (s->host.data == NULL) {
                ngx_socks_server_error(s, NGX_ENOMEM, "Could not alloc memory for upstream address: %*s", s->host.len, dest_address);
                return NGX_ERROR;
            }

            len = sizeof (struct sockaddr_in);
            break;
        default: //IPv6
            break;
    }

    peer->sockaddr = ngx_pcalloc(c->pool, len);
    if (peer->sockaddr == NULL) {
        ngx_socks_server_error(s, NGX_ENOMEM, "SOCKS: Could not alloc memory for peer sockaddr");
        
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

    return ngx_socks_v5_connect_requested_host(s, c, peer);    
}

static ngx_int_t 
ngx_socks_v5_connect_requested_host(ngx_socks_session_t *s, ngx_connection_t *c, ngx_addr_t *peer) {
    ngx_int_t rc;    

    ngx_socks_proxy_ctx_t *proxy = ngx_pcalloc(s->connection->pool, sizeof (*proxy));
    if (proxy == NULL) {
        ngx_socks_server_error(s, NGX_ENOMEM, "Could not create buffer for upstream context");
        return NGX_ERROR;
    }
    
    proxy->upstream.data = s;
    s->proxy = proxy;

    proxy->upstream.sockaddr = peer->sockaddr;
    proxy->upstream.socklen = peer->socklen;
    proxy->upstream.name = &peer->name;
    proxy->upstream.get = ngx_event_get_peer;
    proxy->upstream.log = s->connection->log;
    proxy->upstream.log_error = NGX_ERROR_ERR;

    ngx_log_debug(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0, "requesting url: %V:%ud ", &peer->name, ntohs(((struct sockaddr_in*) peer->sockaddr)->sin_port));

    rc = ngx_event_connect_peer(&proxy->upstream);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_socks_server_error(s, NGX_ECONNREFUSED, "Could not connect to upstream: %V", &peer->name);
        return NGX_ERROR;
    }

    proxy->upstream.connection->read->handler = ngx_socks_proxy_block_read;
    proxy->upstream.connection->write->handler = ngx_socks_proxy_connected;

    ngx_socks_core_srv_conf_t *cscf;

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    ngx_add_timer(proxy->upstream.connection->read, cscf->timeout);

    proxy->upstream.connection->data = s;
    proxy->upstream.connection->pool = s->connection->pool;
    
    return NGX_OK;
}

static u_char*
ngx_pstrdup_n(ngx_pool_t *pool, u_char *src, ngx_int_t size) {
    u_char *dst;

    dst = ngx_pnalloc(pool, size);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src, size);

    return dst;
}

static void
ngx_socks_v5_request(ngx_event_t *rev) {
    ngx_int_t rc;
    size_t buf_len;
    u_char address_type;
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    const ngx_int_t expected_request_len = 6;

    c = rev->data;
    s = c->data;

    c->log->action = "in waiting client request state";
    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "SOCKS: received client request");

    rc = ngx_socks_read_command(s, c);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    buf_len = s->buffer->last - s->buffer->pos + 1;
    
    if (buf_len <= expected_request_len) {
        return;
    }

    if(*(s->buffer->pos) != 0x05) {
        ngx_socks_bad_request(s, 0, "Received unknown request, the first byte is not 0x05");
        return;
    }

    address_type = *(s->buffer->pos + 3);
    switch (address_type) {
        case 0x01:
            if (buf_len <= expected_request_len + 4) {
                return;
            }
            s->port = *(short*) (s->buffer->pos + 8); //already network order

            ngx_socks_v5_connect_upstream(s, c, AF_INET, (struct in_addr*) (s->buffer->pos + 4), s->port);
            return;
            
        case 0x03:
            if (buf_len <= expected_request_len + *(s->buffer->pos + 4) + 1) {
                return;
            }
            s->port = *(short*) (s->buffer->pos + 4 + *(s->buffer->pos + 4) + 1); //already network order

            ngx_socks_v5_resolve_name(s, c, s->buffer->pos + 5, *(s->buffer->pos + 4));
            return;
            
        case 0x04:
            ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, c->log, 0, "Received currently unsupported IPV6 address");
            return;
            
        default:
            ngx_log_debug1(NGX_LOG_DEBUG_SOCKS, c->log, 0, "Received unknown address type: %d", address_type);
            ngx_socks_close_connection(c);
            return;
    }
}

static void 
ngx_socks_proxy_block_read(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, rev->log, 0, "socks block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_socks_server_error(s, 0, "Failed in socks_proxy_block_read, closing connections");
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

static void 
ngx_socks_del_timer(ngx_socks_session_t *s, ngx_event_t *ev, char *message) {
    if(ev->timer_set) {
        ngx_del_timer(ev);
        ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0, message);
    }
}

static void 
ngx_socks_proxy_connected(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    size_t response_head_len = sizeof (request_response_head);

    c = rev->data;
    s = c->data;
    
    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, rev->log, 0, "socks check if upstream has been connected");
    
    if (ngx_http_upstream_test_connect(c) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, rev->log, 0, "socks upstream has not been connected, will try again later");
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_SOCKS, rev->log, 0, "socks upstream connected, start to send response to client");

    ngx_memcpy(s->out_buffer->pos, &request_response_head, response_head_len);
    s->out_buffer->last += response_head_len;
    
    ngx_socks_request_response_t* response = (ngx_socks_request_response_t*) s->out_buffer->pos;
    int response_addr_len = strlen((char*) server_host);

    *response->bind_address = response_addr_len;
    ngx_memcpy(response->bind_address + 1, server_host, response_addr_len);

    //TODO: port
    //    ngx_socket_t port = proxy_context->upstream.local->fd;

    *(response->bind_address + response_addr_len + 1) = (u_char) (9999 >> 8);
    *(response->bind_address + response_addr_len + 2) = (u_char) (9999 & 0xFF);

    s->out_buffer->last += response_head_len + response_addr_len + 3;

    ngx_socks_reset_buffer(s->buffer);

    ngx_socks_send(s->connection->write);

    if (ngx_socks_v5_create_buffer(s, c, &s->upstream_buffer, "upstream response") != NGX_OK) {
        return;
    }

    ngx_del_timer(s->proxy->upstream.connection->read);
    
    s->proxy->upstream.connection->read->handler = ngx_socks_v5_pass_through;
    s->proxy->upstream.connection->write->handler = ngx_socks_v5_pass_through;
    
    ngx_socks_del_timer(s, s->connection->read, "Delete client read timer");
    ngx_socks_del_timer(s, s->connection->write, "Delete client write timer");
    ngx_socks_del_timer(s, s->proxy->upstream.connection->read, "Delete upstream read timer");
    ngx_socks_del_timer(s, s->proxy->upstream.connection->write, "Delete upstream write timer");

    s->socks_state = ngx_socks_state_pass_through;
}
