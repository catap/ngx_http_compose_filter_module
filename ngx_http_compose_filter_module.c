
/*
 * Copyright (C) Maxim Dounin
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t         enable;
} ngx_http_compose_conf_t;


typedef struct {
    ngx_uint_t         done;
    ngx_array_t        parts;
} ngx_http_compose_ctx_t;


static void *ngx_http_compose_create_conf(ngx_conf_t *cf);
static char *ngx_http_compose_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_compose_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_compose_body_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_compose_commands[] = {

    { ngx_string("compose"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compose_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_compose_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_compose_init,         /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_compose_create_conf,  /* create location configuration */
    ngx_http_compose_merge_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_compose_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_compose_module_ctx,  /* module context */
    ngx_http_compose_commands,     /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_module_t  ngx_http_compose_body_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_compose_body_init,    /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


ngx_module_t  ngx_http_compose_body_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_compose_body_module_ctx,  /* module context */
    NULL,                          /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_compose_header_filter(ngx_http_request_t *r)
{
    off_t                     len;
    ngx_uint_t                i;
    ngx_str_t                *uri;
    ngx_list_part_t          *part;
    ngx_table_elt_t          *header;
    ngx_http_compose_conf_t  *conf;
    ngx_http_compose_ctx_t   *ctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_compose_filter_module);

    if (!conf->enable) {
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "compose header filter");

    /* create context */

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_compose_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&ctx->parts, r->pool, 1, sizeof(ngx_str_t))
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }


    /*
     * Collect all X-Compose headers (or combined one?), store in context
     * for our body filter to make actual subrequests.  Hide them from the
     * response.
     */

    part = &r->headers_out.headers.part;
    header = part->elts;
    len = -1;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (header[i].key.len == sizeof("X-Compose-Length") - 1
            && ngx_strncasecmp(header[i].key.data, "X-Compose-Length",
                               sizeof("X-Compose-Length") - 1)
               == 0)
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "compose body filter: bingo, %V, %V",
                           &header[i].key, &header[i].value);

            header[i].hash = 0;

            len = ngx_atoof(header[i].value.data, header[i].value.len);
        }

        if (header[i].key.len == sizeof("X-Compose") - 1
            && ngx_strncasecmp(header[i].key.data, "X-Compose",
                               sizeof("X-Compose") - 1)
               == 0)
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "compose body filter: bingo, %V, %V",
                           &header[i].key, &header[i].value);

            header[i].hash = 0;

            /*
             * XXX multiple headers with the same name must be combinable,
             * see RFC 2616 4.2 Message Headers
             */

            uri = ngx_array_push(&ctx->parts);
            if (uri == NULL) {
                return NGX_ERROR;
            }

            *uri = header[i].value;
        }
    }

    if (ctx->parts.nelts == 0) {
        return ngx_http_next_header_filter(r);
    }

    r->headers_out.content_length_n = len;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_compose_filter_module);

    if (len != -1) {
        r->allow_ranges = 1;
        r->late_ranges = 1;
        r->headers_out.status_line.len = 0;

    } else {
        ngx_http_clear_accept_ranges(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_compose_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_str_t                 *uri, args;
    ngx_int_t                  rc;
    ngx_uint_t                 i, flags, last;
    ngx_http_request_t        *sr;
    ngx_http_compose_ctx_t    *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "compose body filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_compose_filter_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compose body filter: no ctx");
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compose body filter: done");
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "compose body filter, doing work");

    /*
     * Ignore body that comes to us, replace it with subrequests.
     */

    last = 0;

    for ( ; in; in = in->next) {
        in->buf->pos = in->buf->last;
        if (in->buf->last_buf) {
            last = 1;
            in->buf->last_buf = 0;
        }
    }

    if (!last) {
        return NGX_OK;
    }

    ctx->done = 1;

    uri = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {

        args.len = 0;
        args.data = NULL;
        flags = 0;

        if (ngx_http_parse_unsafe_uri(r, &uri[i], &args, &flags) != NGX_OK) {
            return NGX_ERROR;
        }

        rc = ngx_http_subrequest(r, &uri[i], &args, &sr, NULL, flags);

        if (rc == NGX_ERROR || rc == NGX_DONE) {
            return rc;
        }
    }

    return ngx_http_send_special(r, NGX_HTTP_LAST);
}


static void *
ngx_http_compose_create_conf(ngx_conf_t *cf)
{
    ngx_http_compose_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compose_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_compose_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_compose_conf_t *prev = parent;
    ngx_http_compose_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_compose_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_compose_header_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_compose_body_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_compose_body_filter;

    return NGX_OK;
}
