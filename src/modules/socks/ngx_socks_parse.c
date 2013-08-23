#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_socks.h"
#include "ngx_socks_v5_module.h"


#define char2hex(c) ({       \
    char h[2];          \
    char_to_hex((c), h);   \
})

char* char_to_hex(char c, char* hex) {
    const char* hex_symbols="0123456789ABCDEF";

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

ngx_int_t ngx_socks_v5_parse_greeting_command(ngx_socks_session_t *s) {
    u_char nmethod;
    
    //only the first two bytes
    if (s->buffer->last > s->buffer->pos ){
        if(*(s->buffer->pos) != '5' ) { //TODO: should be 0x05 instead of '5'
            return NGX_SOCKS_PARSE_INVALID_COMMAND;
        }
    }
    
    if (s->buffer->last - s->buffer->pos + 1 <= 2) {
        return NGX_AGAIN;
    }
    
    u_char nmethods = *(s->buffer->pos + 1) - '0'; //TODO: should be number instead of '0' + number
    
    if (s->buffer->last - s->buffer->pos + 1 < 2 + nmethods) {
        return NGX_AGAIN;
    }
    
    //choose the auth methods in order: no auth, GSSAPI, USER/PWD
    for(nmethod = 0; nmethod < sizeof(supported_auth_methods); nmethod++) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "checking auth method: '%*s'", 2, char2hex(supported_auth_methods[nmethod]));
        for(size_t method = 0; method < nmethods; method++) {
            if(*(s->buffer->pos + 2 + method) - '0' == supported_auth_methods[nmethod]) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "Found matched method at %uz: '%*s'", nmethod, 2, char2hex(supported_auth_methods[nmethod]));
                s->auth_method = supported_auth_methods[nmethod];
                return NGX_OK;
            }
        }
    }
    
    return NGX_OK;
}

/*
 parse a full command, or keep the buffer unchanged
 */
ngx_int_t
ngx_socks_v5_parse_command(ngx_socks_session_t *s) {
    u_char ch, *p;

    ngx_socks_state_e socks_state = s->socks_state;
    switch(socks_state){
        case ngx_socks_state_start:
            if(ngx_socks_v5_parse_greeting_command(s) == NGX_OK){
                s->socks_state = ngx_socks_state_wait_request;
            }
            break;
        default:
            goto invalid;
    }
    
    for(p = s->buffer->pos; p < s->buffer->last; p++){
        ch = *p;
        
        if(ch != 0x05){
            goto invalid;
        }
        
    }
    
invalid:
    return NGX_SOCKS_PARSE_INVALID_COMMAND;
}

ngx_int_t
ngx_socks_v5_parse_command1(ngx_socks_session_t *s) {
    u_char ch, *p, *c, c0, c1, c2, c3;
    ngx_str_t *arg;

    enum {
        sw_start = 0,
        sw_spaces_before_argument,
        sw_argument,
        sw_almost_done
    } state;

    state = s->state;

    for (p = s->buffer->pos; p < s->buffer->last; p++) {
        ch = *p;

        switch (state) {

                /* SMTP command */
            case sw_start:
                if (ch == ' ' || ch == CR || ch == LF) {
                    c = s->buffer->start;

                    if (p - c == 4) {

                        c0 = ngx_toupper(c[0]);
                        c1 = ngx_toupper(c[1]);
                        c2 = ngx_toupper(c[2]);
                        c3 = ngx_toupper(c[3]);

                        if (c0 == 'H' && c1 == 'E' && c2 == 'L' && c3 == 'O') {
                            s->command = NGX_SMTP_HELO;

                        } else if (c0 == 'E' && c1 == 'H' && c2 == 'L' && c3 == 'O') {
                            s->command = NGX_SMTP_EHLO;

                        } else if (c0 == 'Q' && c1 == 'U' && c2 == 'I' && c3 == 'T') {
                            s->command = NGX_SMTP_QUIT;

                        } else if (c0 == 'A' && c1 == 'U' && c2 == 'T' && c3 == 'H') {
                            s->command = NGX_SMTP_AUTH;

                        } else if (c0 == 'N' && c1 == 'O' && c2 == 'O' && c3 == 'P') {
                            s->command = NGX_SMTP_NOOP;

                        } else if (c0 == 'M' && c1 == 'A' && c2 == 'I' && c3 == 'L') {
                            s->command = NGX_SMTP_MAIL;

                        } else if (c0 == 'R' && c1 == 'S' && c2 == 'E' && c3 == 'T') {
                            s->command = NGX_SMTP_RSET;

                        } else if (c0 == 'R' && c1 == 'C' && c2 == 'P' && c3 == 'T') {
                            s->command = NGX_SMTP_RCPT;

                        } else if (c0 == 'V' && c1 == 'R' && c2 == 'F' && c3 == 'Y') {
                            s->command = NGX_SMTP_VRFY;

                        } else if (c0 == 'E' && c1 == 'X' && c2 == 'P' && c3 == 'N') {
                            s->command = NGX_SMTP_EXPN;

                        } else if (c0 == 'H' && c1 == 'E' && c2 == 'L' && c3 == 'P') {
                            s->command = NGX_SMTP_HELP;

                        } else {
                            goto invalid;
                        }
#if (NGX_MAIL_SSL)
                    } else if (p - c == 8) {

                        if ((c[0] == 'S' || c[0] == 's')
                                && (c[1] == 'T' || c[1] == 't')
                                && (c[2] == 'A' || c[2] == 'a')
                                && (c[3] == 'R' || c[3] == 'r')
                                && (c[4] == 'T' || c[4] == 't')
                                && (c[5] == 'T' || c[5] == 't')
                                && (c[6] == 'L' || c[6] == 'l')
                                && (c[7] == 'S' || c[7] == 's')) {
                            s->command = NGX_SMTP_STARTTLS;

                        } else {
                            goto invalid;
                        }
#endif
                    } else {
                        goto invalid;
                    }

                    switch (ch) {
                        case ' ':
                            state = sw_spaces_before_argument;
                            break;
                        case CR:
                            state = sw_almost_done;
                            break;
                        case LF:
                            goto done;
                    }
                    break;
                }

                if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')) {
                    goto invalid;
                }

                break;

            case sw_spaces_before_argument:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        state = sw_almost_done;
                        s->arg_end = p;
                        break;
                    case LF:
                        s->arg_end = p;
                        goto done;
                    default:
                        if (s->args.nelts <= 10) {
                            state = sw_argument;
                            s->arg_start = p;
                            break;
                        }
                        goto invalid;
                }
                break;

            case sw_argument:
                switch (ch) {
                    case ' ':
                    case CR:
                    case LF:
                        arg = ngx_array_push(&s->args);
                        if (arg == NULL) {
                            return NGX_ERROR;
                        }
                        arg->len = p - s->arg_start;
                        arg->data = s->arg_start;
                        s->arg_start = NULL;

                        switch (ch) {
                            case ' ':
                                state = sw_spaces_before_argument;
                                break;
                            case CR:
                                state = sw_almost_done;
                                break;
                            case LF:
                                goto done;
                        }
                        break;

                    default:
                        break;
                }
                break;

            case sw_almost_done:
                switch (ch) {
                    case LF:
                        goto done;
                    default:
                        goto invalid;
                }
        }
    }

    s->buffer->pos = p;
    s->state = state;

    return NGX_AGAIN;

done:

    s->buffer->pos = p + 1;

    if (s->arg_start) {
        arg = ngx_array_push(&s->args);
        if (arg == NULL) {
            return NGX_ERROR;
        }
        arg->len = s->arg_end - s->arg_start;
        arg->data = s->arg_start;
        s->arg_start = NULL;
    }

    s->state = (s->command != NGX_SMTP_AUTH) ? sw_start : sw_argument;

    return NGX_OK;

invalid:

    s->state = sw_start;
    s->arg_start = NULL;

    return NGX_SOCKS_PARSE_INVALID_COMMAND;
}

ngx_int_t
ngx_socks_auth_parse(ngx_socks_session_t *s, ngx_connection_t *c) {
    ngx_str_t *arg;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    arg = s->args.elts;

    if (arg[0].len == 5) {

        if (ngx_strncasecmp(arg[0].data, (u_char *) "LOGIN", 5) == 0) {

            if (s->args.nelts == 1) {
                return NGX_MAIL_AUTH_LOGIN;
            }

            if (s->args.nelts == 2) {
                return NGX_MAIL_AUTH_LOGIN_USERNAME;
            }

            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        if (ngx_strncasecmp(arg[0].data, (u_char *) "PLAIN", 5) == 0) {

            if (s->args.nelts == 1) {
                return NGX_MAIL_AUTH_PLAIN;
            }

            if (s->args.nelts == 2) {
                return ngx_socks_auth_plain(s, c, 1);
            }
        }

        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    if (arg[0].len == 8) {

        if (s->args.nelts != 1) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        if (ngx_strncasecmp(arg[0].data, (u_char *) "CRAM-MD5", 8) == 0) {
            return NGX_MAIL_AUTH_CRAM_MD5;
        }
    }

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}

