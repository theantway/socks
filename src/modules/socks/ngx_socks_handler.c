#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_socks.h"

static void ngx_socks_init_session(ngx_connection_t *c, ngx_socks_conf_ctx_t* config_ctx);

void ngx_socks_init_connection(ngx_connection_t *c) {
    ngx_uint_t i;
    ngx_socks_port_t *port;
    struct sockaddr *sa;
    struct sockaddr_in *sin;
    ngx_socks_in_addr_t *addr;
    ngx_socks_addr_conf_t *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6 *sin6;
    ngx_socks_in6_addr_t *addr6;
#endif


    /* find the server configuration for the address:port */
    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_socks_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) sa;
                addr6 = port->addrs;

                /* the last address is "*" */
                for (i = 0; i < port->naddrs - 1; i++) {
                    if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                        break;
                    }
                }

                addr_conf = &addr6[i].conf;
                
                break;
#endif

            default: /* AF_INET */
                sin = (struct sockaddr_in *) sa;
                addr = port->addrs;

                /* the last address is "*" */
                for (i = 0; i < port->naddrs - 1; i++) {
                    if (addr[i].addr == sin->sin_addr.s_addr) {
                        break;
                    }
                }

                addr_conf = &addr[i].conf;

                break;
        }
    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                addr6 = port->addrs;
                addr_conf = &addr6[0].conf;
                break;
#endif

            default: /* AF_INET */
                addr = port->addrs;
                addr_conf = &addr[0].conf;
                break;
        }
    }

    ngx_socks_init_session(c, addr_conf->ctx);
}

static void
ngx_socks_init_session(ngx_connection_t *c, ngx_socks_conf_ctx_t* config_ctx) {
    ngx_socks_session_t *s;
    ngx_socks_core_srv_conf_t *cscf;
    ngx_socks_log_ctx_t* log_ctx;

    cscf = config_ctx->srv_conf[ngx_socks_core_module.ctx_index];

    s = ngx_pcalloc(c->pool, sizeof (ngx_socks_session_t));
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "SOCKS: Could not alloc memory for session, closing connection");

        ngx_socks_close_connection(c);
        return;
    }

    s->connection = c;
    s->resolver_ctx = NULL;
    s->protocol = cscf->protocol->type;
    s->srv_conf = config_ctx->srv_conf;
    s->main_conf = config_ctx->main_conf;
    
    s->ctx = ngx_pcalloc(c->pool, sizeof (void *) * ngx_socks_max_module);
    if (s->ctx == NULL) {
        ngx_socks_server_error(s, NGX_ENOMEM, "SOCKS: Could not alloc memory for socks modules");
        return;
    }
   
    c->data = s;

    log_ctx = ngx_palloc(c->pool, sizeof (ngx_socks_log_ctx_t));
    if (log_ctx == NULL) {
        ngx_socks_server_error(s, NGX_ENOMEM, "SOCKS: Could not alloc memory for log context");
        
        return;
    }
    
    log_ctx->client = &c->addr_text;
    log_ctx->session = s;
    
    c->log_error = NGX_ERROR_INFO;
    c->log->connection = c->number;
    c->log->data = log_ctx;
    c->log->handler = ngx_socks_log_handler;
    c->log->log_level = NGX_LOG_DEBUG_SOCKS | NGX_LOG_DEBUG_CORE;
    
    c->write->handler = ngx_socks_send;

    ngx_log_debug2(NGX_LOG_DEBUG_SOCKS, c->log, 0, "client connected, connection: %p session: %p", c, s);
    
    //TODO: FIND the protocol by the first byte of incoming request, 0x04 or 0x05
    cscf->protocol->init_session(s, c);
}

void ngx_socks_send(ngx_event_t *wev) {
    ngx_int_t n;
    ngx_buf_t * buf;
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    ngx_socks_core_srv_conf_t *cscf;

    c = wev->data;
    s = c->data;
    buf = s->out_buffer;
    
    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_socks_proxy_close_session(s);
        return;
    }

    if (buf->last == buf->pos) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "handle write event failed when nothing to send");
            ngx_socks_proxy_close_session(s);
        }

        return;
    }

    while(buf->last > buf->pos) {
        n = c->send(c, buf->pos, buf->last - buf->pos);

        if (n <= 0) {
            break;
        }

        buf->pos += n;
    }
    
    if(buf->pos == buf->last) {
        buf->pos = buf->start;
        buf->last = buf->start;
    }
    
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (s->quit) {
        ngx_log_debug(NGX_LOG_DEBUG_SOCKS, c->log, 0, "SOCKS: close connection because the session has quit flag");
        ngx_socks_proxy_close_session(s);
        return;
    }

    if (s->blocked) {
        c->read->handler(c->read);
    }

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "SOCKS: failed to send response, closing session");
        ngx_socks_proxy_close_session(s);
        return;
    }

    /* n == NGX_AGAIN */

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "handle write event failed after send");
        ngx_socks_proxy_close_session(s);
        return;
    }
}

ngx_int_t ngx_socks_read_command(ngx_socks_session_t *s, ngx_connection_t *c) {
    ssize_t n;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == NGX_ERROR || n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "failed to recv, closing session");
        ngx_socks_proxy_close_session(s);
        return NGX_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "failed to handle read event, closing session");
            ngx_socks_server_error(s, NGX_ETIMEDOUT, "failed to handle read event, closing session");
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    return NGX_OK;
}

void 
ngx_socks_server_error(ngx_socks_session_t *s, ngx_err_t err, char* fmt, ...) {
    ngx_socks_core_srv_conf_t *cscf;
    ngx_connection_t *c;
    va_list args;
    
    c = s->connection;
    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
    
    va_start(args, fmt);
    ngx_log_error(NGX_LOG_ERR, c->log, err, fmt, args);
    va_end(args);
    
    //anything not 0x04, 0x05 indicates an error
    *(s->out_buffer->pos) = 0xFF;
    s->out_buffer->last ++;

    //we should close the connection after send the error response
    s->quit = 1;
    
    ngx_socks_send(s->connection->write);
}

void ngx_socks_proxy_close_session(ngx_socks_session_t *s) {
    ngx_connection_t *c = s->connection;
    
    if(s->resolver_ctx != NULL) {
        s->resolver_ctx->state = NGX_RESOLVE_TIMEDOUT;
        ngx_resolve_name_done(s->resolver_ctx);
        s->resolver_ctx = NULL;
    }
    
    if (s->proxy && s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_SOCKS, c->log, 0,
                "close socks upstream connection: %d", s->proxy->upstream.connection->fd);
        ngx_close_connection(s->proxy->upstream.connection);
    }
    
    ngx_socks_close_connection(c);
}

void ngx_socks_close_connection(ngx_connection_t *c) {
    ngx_log_debug1(NGX_LOG_DEBUG_SOCKS, c->log, 0, "close socks client connection: %d", c->fd);

    c->destroyed = 1;

    ngx_close_connection(c);

    ngx_destroy_pool(c->pool);
}

u_char* ngx_socks_log_handler(ngx_log_t *log, u_char *buf, size_t len) {
    u_char *p;
    ngx_socks_session_t *s;
    ngx_socks_log_ctx_t *ctx;

    ctx = log->data;
    s = ctx->session;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    if (s == NULL) {
        return p;
    }

    if (s->proxy == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);

    return p;
}
