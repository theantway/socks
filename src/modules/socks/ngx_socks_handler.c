#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_socks.h"

static void ngx_socks_init_session(ngx_connection_t *c);

void ngx_socks_init_connection(ngx_connection_t *c) {
    ngx_uint_t i;
    ngx_socks_port_t *port;
    struct sockaddr *sa;
    struct sockaddr_in *sin;
    ngx_socks_log_ctx_t *ctx;
    ngx_socks_in_addr_t *addr;
    ngx_socks_session_t *s;
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

    s = ngx_pcalloc(c->pool, sizeof (ngx_socks_session_t));
    if (s == NULL) {
        ngx_socks_close_connection(c);
        return;
    }

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;
    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
            c->number, &c->addr_text, s->addr_text);

    ctx = ngx_palloc(c->pool, sizeof (ngx_socks_log_ctx_t));
    if (ctx == NULL) {
        ngx_socks_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_socks_log_error;
    c->log->data = ctx;
    c->log->log_level = NGX_LOG_DEBUG_CORE | NGX_LOG_DEBUG_SOCKS;
    
    c->log_error = NGX_ERROR_INFO;

    ngx_socks_init_session(c);
}

static void
ngx_socks_init_session(ngx_connection_t *c) {
    ngx_socks_session_t *s;
    ngx_socks_core_srv_conf_t *cscf;

    s = c->data;

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    s->protocol = cscf->protocol->type;

    s->ctx = ngx_pcalloc(c->pool, sizeof (void *) * ngx_socks_max_module);
    if (s->ctx == NULL) {
        ngx_socks_session_internal_server_error(s);
        return;
    }

    c->write->handler = ngx_socks_send;

    cscf->protocol->init_session(s, c);
}

void ngx_socks_send(ngx_event_t *wev) {
    ngx_int_t n;
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    ngx_socks_core_srv_conf_t *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_socks_proxy_close_session(s);
        return;
    }

    if (s->out_buffer->last == s->out_buffer->pos) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_socks_proxy_close_session(s);
        }

        return;
    }

    while(s->out_buffer->last > s->out_buffer->pos) {
        ngx_buf_t *buf = s->out_buffer;
        
        n = c->send(c, buf->pos, buf->last - buf->pos);

        if (n <= 0) {
            break;
        }

        buf->pos += n;
    }
    
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (s->quit) {
        ngx_socks_proxy_close_session(s);
        return;
    }

    if (s->blocked) {
        c->read->handler(c->read);
    }

    if (n == NGX_ERROR) {
        ngx_socks_proxy_close_session(s);
        return;
    }

    /* n == NGX_AGAIN */

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_socks_proxy_close_session(s);
        return;
    }
}

ngx_int_t ngx_socks_read_command(ngx_socks_session_t *s, ngx_connection_t *c) {
    ssize_t n;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == NGX_ERROR || n == 0) {
        ngx_socks_proxy_close_session(s);
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

    return NGX_OK;
}

void ngx_socks_session_internal_server_error(ngx_socks_session_t *s) {
    ngx_socks_core_srv_conf_t *cscf;

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    s->quit = 1;

    ngx_socks_send(s->connection->write);
}

void ngx_socks_proxy_close_session(ngx_socks_session_t *s) {
    if (s->proxy && s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_SOCKS, s->connection->log, 0,
                "close socks proxy connection: %d",
                s->proxy->upstream.connection->fd);

        ngx_close_connection(s->proxy->upstream.connection);
    }

    ngx_socks_close_connection(s->connection);
}

void ngx_socks_close_connection(ngx_connection_t *c) {
    ngx_pool_t *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_SOCKS, c->log, 0,
            "close socks connection: %d", c->fd);

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}

u_char* ngx_socks_log_error(ngx_log_t *log, u_char *buf, size_t len) {
    u_char *p;
    ngx_socks_session_t *s;
    ngx_socks_log_ctx_t *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    if (s->proxy == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);

    return p;
}
