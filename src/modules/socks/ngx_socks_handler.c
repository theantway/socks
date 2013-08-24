#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_socks.h"

static void ngx_socks_init_session(ngx_connection_t *c);

void ngx_socks_init_buf_chain(ngx_socks_buf_chains_t *chain, ngx_pool_t *pool) {
    chain->pool = pool;
    chain->chains = NULL;
    chain->free_chains = NULL;
}

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

    ngx_socks_init_buf_chain(&s->in_buf_chain, c->pool);
    ngx_socks_init_buf_chain(&s->out_buf_chain, c->pool);
    
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
    c->log->action = "sending client greeting line";
    c->log->log_level = NGX_LOG_DEBUG_CORE | NGX_LOG_DEBUG_SOCKS;
    
    c->log_error = NGX_ERROR_INFO;

#if (NGX_SOCKS_SSL)
    {
        ngx_socks_ssl_conf_t *sslcf;

        sslcf = ngx_socks_get_module_srv_conf(s, ngx_socks_ssl_module);

        if (sslcf->enable) {
            c->log->action = "SSL handshaking";

            ngx_socks_ssl_init_connection(&sslcf->ssl, c);
            return;
        }

        if (addr_conf->ssl) {

            c->log->action = "SSL handshaking";

            if (sslcf->ssl.ctx == NULL) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "no \"ssl_certificate\" is defined "
                        "in server listening on SSL port");
                ngx_socks_close_connection(c);
                return;
            }

            ngx_socks_ssl_init_connection(&sslcf->ssl, c);
            return;
        }

    }
#endif

    ngx_socks_init_session(c);
}


#if (NGX_MAIL_SSL)

void
ngx_socks_starttls_handler(ngx_event_t *rev) {
    ngx_connection_t *c;
    ngx_socks_session_t *s;
    ngx_socks_ssl_conf_t *sslcf;

    c = rev->data;
    s = c->data;
    s->starttls = 1;

    c->log->action = "in starttls state";

    sslcf = ngx_socks_get_module_srv_conf(s, ngx_socks_ssl_module);

    ngx_socks_ssl_init_connection(&sslcf->ssl, c);
}

static void
ngx_socks_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c) {
    ngx_socks_session_t *s;
    ngx_socks_core_srv_conf_t *cscf;

    if (ngx_ssl_create_connection(ssl, c, 0) == NGX_ERROR) {
        ngx_socks_close_connection(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {

        s = c->data;

        cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

        ngx_add_timer(c->read, cscf->timeout);

        c->ssl->handler = ngx_socks_ssl_handshake_handler;

        return;
    }

    ngx_socks_ssl_handshake_handler(c);
}

static void
ngx_socks_ssl_handshake_handler(ngx_connection_t *c) {
    ngx_socks_session_t *s;
    ngx_socks_core_srv_conf_t *cscf;

    if (c->ssl->handshaked) {

        s = c->data;

        if (s->starttls) {
            cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

            c->read->handler = cscf->protocol->init_protocol;
            c->write->handler = ngx_socks_send;

            cscf->protocol->init_protocol(c->read);

            return;
        }

        c->read->ready = 0;

        ngx_socks_init_session(c);
        return;
    }

    ngx_socks_close_connection(c);
}

#endif

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

#if (NGX_MAIL_SSL)

ngx_int_t
ngx_socks_starttls_only(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_socks_ssl_conf_t *sslcf;

    if (c->ssl) {
        return 0;
    }

    sslcf = ngx_socks_get_module_srv_conf(s, ngx_socks_ssl_module);

    if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
        return 1;
    }

    return 0;
}

#endif

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

    if (s->out_buf_chain.chains == NULL) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_socks_proxy_close_session(s);
        }

        return;
    }

    ngx_chain_t * chain = s->out_buf_chain.chains;
    while(chain != NULL) {
        ngx_buf_t *buf = chain->buf;
        
        n = c->send(c, buf->pos, buf->last - buf->pos);

        if (n <= 0) {
            break;
        }

        buf->pos += n;
        
        if(buf->pos == buf->last) {
            ngx_chain_t* current_chain = chain;
            chain = chain->next;
            
            ngx_socks_free_buf_chain(&s->out_buf_chain, current_chain);
            
            continue;
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

        return;
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

void
ngx_socks_auth(ngx_socks_session_t *s, ngx_connection_t *c) {
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    s->login_attempt++;
}

void ngx_socks_session_internal_server_error(ngx_socks_session_t *s) {
    ngx_socks_core_srv_conf_t *cscf;

    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    s->quit = 1;

    ngx_socks_send(s->connection->write);
}

void ngx_socks_proxy_close_session(ngx_socks_session_t *s) {
    if(s->resolver_ctx != NULL) {
        ngx_resolve_name_done(s->resolver_ctx);
        s->resolver_ctx = NULL;
    }
    
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

#if (NGX_MAIL_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_socks_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

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

    p = ngx_snprintf(buf, len, "%s, server: %V",
            s->starttls ? " using starttls" : "",
            s->addr_text);
    len -= p - buf;
    buf = p;

    if (s->login.len == 0) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", login: \"%V\"", &s->login);
    len -= p - buf;
    buf = p;

    if (s->proxy == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);

    return p;
}
