#include "ngx_socks.h"

static ngx_int_t ngx_socks_cmp_conf_addrs(const void *one, const void *two);
static ngx_int_t ngx_socks_add_addrs(ngx_conf_t *cf, ngx_socks_port_t *mport, ngx_socks_conf_addr_t *addr);
static ngx_int_t ngx_socks_add_addrs6(ngx_conf_t *cf, ngx_socks_port_t *mport, ngx_socks_conf_addr_t *addr);

ngx_uint_t ngx_socks_max_module = 0;

static ngx_int_t ngx_socks_add_ports(ngx_conf_t *cf, ngx_array_t *ports, ngx_socks_listen_t *listen) {
    in_port_t p;
    ngx_uint_t i;
    struct sockaddr *sa;
    struct sockaddr_in *sin;
    ngx_socks_conf_port_t *port;
    ngx_socks_conf_addr_t *addr;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6 *sin6;
#endif

    sa = (struct sockaddr *) &listen->sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;
            p = sin6->sin6_port;
            break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            p = 0;
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;
            p = sin->sin_port;
            break;
    }

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {
        if (p == port[i].port && sa->sa_family == port[i].family) {

            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;

    if (ngx_array_init(&port->addrs, cf->temp_pool, 2, sizeof (ngx_socks_conf_addr_t)) != NGX_OK) {
        return NGX_ERROR;
    }

found:

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
    addr->socklen = listen->socklen;
    addr->ctx = listen->ctx;
    addr->bind = listen->bind;
    addr->wildcard = listen->wildcard;
    addr->so_keepalive = listen->so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    addr->tcp_keepidle = listen->tcp_keepidle;
    addr->tcp_keepintvl = listen->tcp_keepintvl;
    addr->tcp_keepcnt = listen->tcp_keepcnt;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    addr->ipv6only = listen->ipv6only;
#endif

    return NGX_OK;
}

static char *
ngx_socks_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports) {
    ngx_uint_t i, p, last, bind_wildcard;
    ngx_listening_t *ls;
    ngx_socks_port_t *mport;
    ngx_socks_conf_port_t *port;
    ngx_socks_conf_addr_t *addr;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                sizeof (ngx_socks_conf_addr_t), ngx_socks_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (addr[last - 1].wildcard) {
            addr[last - 1].bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {

            if (bind_wildcard && !addr[i].bind) {
                i++;
                continue;
            }

            ls = ngx_create_listening(cf, addr[i].sockaddr, addr[i].socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = ngx_socks_init_connection;
            ls->pool_size = 256;

            /* TODO: error_log directive */
            ls->logp = &cf->cycle->new_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

            ls->keepalive = addr[i].so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].tcp_keepidle;
            ls->keepintvl = addr[i].tcp_keepintvl;
            ls->keepcnt = addr[i].tcp_keepcnt;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            ls->ipv6only = addr[i].ipv6only;
#endif

            mport = ngx_palloc(cf->pool, sizeof (ngx_socks_port_t));
            if (mport == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = mport;

            if (i == last - 1) {
                mport->naddrs = last;

            } else {
                mport->naddrs = 1;
                i = 0;
            }

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
                case AF_INET6:
                    if (ngx_socks_add_addrs6(cf, mport, addr) != NGX_OK) {
                        return NGX_CONF_ERROR;
                    }
                    break;
#endif
                default: /* AF_INET */
                    if (ngx_socks_add_addrs(cf, mport, addr) != NGX_OK) {
                        return NGX_CONF_ERROR;
                    }
                    break;
            }

            addr++;
            last--;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_socks_add_addrs(ngx_conf_t *cf, ngx_socks_port_t *mport, ngx_socks_conf_addr_t *addr) {
    u_char *p;
    size_t len;
    ngx_uint_t i;
    ngx_socks_in_addr_t *addrs;
    struct sockaddr_in *sin;
    u_char buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool, mport->naddrs * sizeof (ngx_socks_in_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].ctx;

        len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t ngx_socks_add_addrs6(ngx_conf_t *cf, ngx_socks_port_t *mport, ngx_socks_conf_addr_t *addr) {
    u_char *p;
    size_t len;
    ngx_uint_t i;
    ngx_socks_in6_addr_t *addrs6;
    struct sockaddr_in6 *sin6;
    u_char buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool, mport->naddrs * sizeof (ngx_socks_in6_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].ctx;

        len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs6[i].conf.addr_text.len = len;
        addrs6[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}

#endif

static ngx_int_t ngx_socks_cmp_conf_addrs(const void *one, const void *two) {
    ngx_socks_conf_addr_t *first, *second;

    first = (ngx_socks_conf_addr_t *) one;
    second = (ngx_socks_conf_addr_t *) two;

    if (first->wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (second->wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return -1;
    }

    if (first->bind && !second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->bind && second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}

static char *
ngx_socks_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *rv;
    ngx_uint_t i, m, mi, s;
    ngx_conf_t pcf;
    ngx_array_t ports;
    ngx_socks_listen_t *listen;
    ngx_socks_module_t *module;
    ngx_socks_conf_ctx_t *ctx;
    ngx_socks_core_srv_conf_t **cscfp;
    ngx_socks_core_main_conf_t *cmcf;

    /* the main socks context */
    ctx = ngx_pcalloc(cf->pool, sizeof (ngx_socks_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_socks_conf_ctx_t **) conf = ctx;

    /* count the number of the socks modules and set up their indices */

    ngx_socks_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_SOCKS_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_socks_max_module++;
    }


    /* the socks main_conf context, it is the same in the all socks contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool, sizeof (void *) * ngx_socks_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the mail null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof (void *) * ngx_socks_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all socks modules
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_SOCKS_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the socks{} block */
    pcf = *cf;
    cf->ctx = ctx;

    cf->module_type = NGX_SOCKS_MODULE;
    cf->cmd_type = NGX_SOCKS_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init socks{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[ngx_socks_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_SOCKS_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init socks{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                        ctx->srv_conf[mi],
                        cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    *cf = pcf;


    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof (ngx_socks_conf_port_t)) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    listen = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (ngx_socks_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_socks_optimize_servers(cf, &ports);
}

static ngx_core_module_t ngx_socks_module_ctx = {
    ngx_string("socks"),
    NULL,
    NULL
};

static ngx_command_t ngx_socks_commands[] = {
    {
        ngx_string("socks"),
        NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
        ngx_socks_block,
        0,
        0,
        NULL
    },
    
    ngx_null_command
};

ngx_module_t ngx_socks_module = {
    NGX_MODULE_V1,

    &ngx_socks_module_ctx, 
    ngx_socks_commands,
    NGX_CORE_MODULE,

    NULL, /*init_master,*/
    NULL, /*init_module,*/
    NULL, /*init_process,*/
    NULL, /*init_thread,*/
    NULL, /*exit_thread,*/
    NULL, /*exit_process,*/
    NULL, /*exit_master,*/

    NGX_MODULE_V1_PADDING
};
