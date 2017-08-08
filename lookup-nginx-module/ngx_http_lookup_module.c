#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_variable_value_t       *value;
    ngx_int_t                        start;
    ngx_int_t                        end;
} ngx_http_lookup_t;


typedef struct {
    ngx_radix_tree_t                *tree;
} ngx_http_lookup_trees_t;


typedef struct {
    ngx_http_lookup_t           **low;
    ngx_http_variable_value_t      *default_value;
} ngx_http_lookup_high_ranges_t;


typedef struct {
    ngx_str_node_t                   sn;
    ngx_http_variable_value_t       *value;
    size_t                           offset;
} ngx_http_lookup_variable_value_node_t;


typedef struct {
    ngx_http_variable_value_t       *value;
    ngx_str_t                       *net;
    ngx_http_lookup_high_ranges_t    high;
    ngx_radix_tree_t                *tree;
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
    ngx_pool_t                      *pool;
    ngx_pool_t                      *temp_pool;

    size_t                           data_size;

    ngx_str_t                        include_name;
    ngx_uint_t                       includes;
    ngx_uint_t                       entries;

    unsigned                         ranges:1;
    unsigned                         outside_entries:1;
    unsigned                         allow_binary_include:1;
    unsigned                         binary_include:1;
} ngx_http_lookup_conf_ctx_t;


typedef struct {
    union {
        ngx_http_lookup_trees_t         trees;
        ngx_http_lookup_high_ranges_t   high;
    } u;

    ngx_int_t                        index;
} ngx_http_lookup_ctx_t;

static char *ngx_http_lookup_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_lookup(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static char *ngx_http_lookup_range(ngx_conf_t *cf, ngx_http_lookup_conf_ctx_t *ctx,
    ngx_str_t *value);
static char *ngx_http_lookup_add_range(ngx_conf_t *cf,
    ngx_http_lookup_conf_ctx_t *ctx, ngx_int_t start, ngx_int_t end);
static ngx_http_variable_value_t *ngx_http_lookup_value(ngx_conf_t *cf,
    ngx_http_lookup_conf_ctx_t *ctx, ngx_str_t *value);
static char *ngx_http_lookup_include(ngx_conf_t *cf, ngx_http_lookup_conf_ctx_t *ctx,
    ngx_str_t *name);
static ngx_int_t ngx_http_lookup_include_binary_base(ngx_conf_t *cf,
    ngx_http_lookup_conf_ctx_t *ctx, ngx_str_t *name);
static void ngx_http_lookup_create_binary_base(ngx_http_lookup_conf_ctx_t *ctx);
static u_char *ngx_http_lookup_copy_values(u_char *base, u_char *p,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

static ngx_command_t  ngx_http_lookup_commands[] = {

    { ngx_string("lookup"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
      ngx_http_lookup_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_lookup_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_lookup_module = {
    NGX_MODULE_V1,
    &ngx_http_lookup_module_ctx,              /* module context */
    ngx_http_lookup_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

typedef struct {
    u_char    GEORNG[6];
    u_char    version;
    u_char    ptr_size;
    uint32_t  endianness;
    uint32_t  crc32;
} ngx_http_lookup_header_t;

static ngx_http_lookup_header_t  ngx_http_lookup_header = {
    { 'C', 'O', 'M', 'R', 'N', 'G' }, 0, sizeof(void *), 0x12345678, 0
};

static ngx_int_t
ngx_http_lookup_range_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_lookup_ctx_t *ctx = (ngx_http_lookup_ctx_t *) data;

    ngx_uint_t             n;
    ngx_http_lookup_t  *range;

    ngx_http_variable_value_t  *key;
    ngx_int_t              k;

    key = ngx_http_get_flushed_variable(r, ctx->index);

    if (key == NULL || key->not_found) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "search not found");

        return NGX_ERROR;
    }

  	k = ngx_atoi(key->data, key->len);
    if (k == NGX_ERROR || k < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid input: %s", key->data);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "search started: %v", v);

    *v = *ctx->u.high.default_value;

    if (ctx->u.high.low) {
        range = ctx->u.high.low[k >> 32];

        if (range) {
            n = k & 0xffffffff;
            do {
                if (n >= (ngx_uint_t) range->start
                    && n <= (ngx_uint_t) range->end)
                {
                    *v = *range->value;
                    break;
                }
            } while ((++range)->value);
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lookup: %v", v);
    return NGX_OK;
}

static char *
ngx_http_lookup_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *rv;
    size_t                    len;
    ngx_str_t                *value, name;
    ngx_uint_t                i;
    ngx_conf_t                save;
    ngx_pool_t               *pool;
    ngx_array_t              *a;
    ngx_http_variable_t      *var;
    ngx_http_lookup_ctx_t       *lookup;
    ngx_http_lookup_conf_ctx_t   ctx;

    value = cf->args->elts;

    lookup = ngx_palloc(cf->pool, sizeof(ngx_http_lookup_ctx_t));
    if (lookup == NULL) {
        return NGX_CONF_ERROR;
    }

    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    if (cf->args->nelts == 3) {

        lookup->index = ngx_http_get_variable_index(cf, &name);
        if (lookup->index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        name = value[2];

        if (name.data[0] != '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid variable name \"%V\"", &name);
            return NGX_CONF_ERROR;
        }

        name.len--;
        name.data++;

    } else {
        lookup->index = -1;
        return NGX_CONF_ERROR;
    }

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ctx, sizeof(ngx_http_lookup_conf_ctx_t));

    ctx.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ctx.temp_pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_rbtree_init(&ctx.rbtree, &ctx.sentinel, ngx_str_rbtree_insert_value);

    ctx.pool = cf->pool;
    ctx.data_size = sizeof(ngx_http_lookup_header_t)
                  + sizeof(ngx_http_variable_value_t)
                  + 0x10000 * sizeof(ngx_http_lookup_t *);
    ctx.allow_binary_include = 1;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = ngx_http_lookup;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (ctx.ranges) {

        if (ctx.high.low && !ctx.binary_include) {
            for (i = 0; i < 0x10000; i++) {
                a = (ngx_array_t *) ctx.high.low[i];

                if (a == NULL || a->nelts == 0) {
                    continue;
                }

                len = a->nelts * sizeof(ngx_http_lookup_t);

                ctx.high.low[i] = ngx_palloc(cf->pool, len + sizeof(void *));
                if (ctx.high.low[i] == NULL) {
                    return NGX_CONF_ERROR;
                }

                ngx_memcpy(ctx.high.low[i], a->elts, len);
                ctx.high.low[i][a->nelts].value = NULL;
                ctx.data_size += len + sizeof(void *);
            }

            if (ctx.allow_binary_include
                && !ctx.outside_entries
                && ctx.entries > 100000
                && ctx.includes == 1)
            {
                ngx_http_lookup_create_binary_base(&ctx);
            }
        }

        if (ctx.high.default_value == NULL) {
            ctx.high.default_value = &ngx_http_variable_null_value;
        }

        lookup->u.high = ctx.high;

        var->get_handler = ngx_http_lookup_range_variable;
        var->data = (uintptr_t) lookup;

        ngx_destroy_pool(ctx.temp_pool);
        ngx_destroy_pool(pool);

    }

    return rv;
}


static char *
ngx_http_lookup(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    char                     *rv;
    ngx_str_t                *value;
    ngx_http_lookup_conf_ctx_t  *ctx;

    rv = NGX_CONF_OK;
    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1) {

        if (ngx_strcmp(value[0].data, "ranges") == 0) {

            if (ctx->tree)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"ranges\" directive must be "
                                   "the first directive inside \"lookup\" block");
                goto failed;
            }

            ctx->ranges = 1;

            rv = NGX_CONF_OK;

            goto done;
        }
    }

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of the lookup parameters");
        goto failed;
    }

    if (ngx_strcmp(value[0].data, "include") == 0) {
        rv = ngx_http_lookup_include(cf, ctx, &value[1]);
        goto done;
    }

    if (ctx->ranges) {
        rv = ngx_http_lookup_range(cf, ctx, value);
    }

done:
    ngx_reset_pool(cf->pool);
    return rv;

failed:
    ngx_reset_pool(cf->pool);
    return NGX_CONF_ERROR;
}


static char *
ngx_http_lookup_range(ngx_conf_t *cf, ngx_http_lookup_conf_ctx_t *ctx,
    ngx_str_t *value)
{
    u_char      *p, *last;
    ngx_int_t   start, end;
    ngx_str_t   *net;

    if (ngx_strcmp(value[0].data, "default") == 0) {

        if (ctx->high.default_value) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "duplicate default lookup range value: \"%V\", old value: \"%v\"",
                &value[1], ctx->high.default_value);
        }

        ctx->high.default_value = ngx_http_lookup_value(cf, ctx, &value[1]);
        if (ctx->high.default_value == NULL) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (ctx->binary_include) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "binary lookup range base \"%s\" cannot be mixed with usual entries",
            ctx->include_name.data);
        return NGX_CONF_ERROR;
    }

    if (ctx->high.low == NULL) {
        ctx->high.low = ngx_pcalloc(ctx->pool,
                                    0x10000 * sizeof(ngx_http_lookup_t *));
        if (ctx->high.low == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx->entries++;
    ctx->outside_entries = 1;

    net = &value[0];

    last = net->data + net->len;

    p = ngx_strlchr(net->data, last, '-');

    if (p == NULL) {
        goto invalid;
    }

    start = ngx_atoi(net->data, p - net->data);

    if (start == NGX_ERROR) {
        goto invalid;
    }

    p++;

    end = ngx_atoi(p, last - p);

    if (end == NGX_ERROR) {
        goto invalid;
    }

    if (start > end) {
        goto invalid;
    }

    ctx->value = ngx_http_lookup_value(cf, ctx, &value[1]);

    if (ctx->value == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->net = net;

    return ngx_http_lookup_add_range(cf, ctx, start, end);

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid range \"%V\"", net);
    return NGX_CONF_ERROR;
}


/* the add procedure is optimized to add a growing up sequence */

static char *
ngx_http_lookup_add_range(ngx_conf_t *cf, ngx_http_lookup_conf_ctx_t *ctx,
    ngx_int_t start, ngx_int_t end)
{
    ngx_int_t             n, h, i, s, e;
    ngx_array_t           *a;
    ngx_http_lookup_t     *range;

    for (n = start; n <= end; n = (n + 0x100000000) & 0xffffffff00000000) {

        h = n >> 32;

        if (n == start) {
            s = n & 0xffffffff;
        } else {
            s = 0;
        }

        if ((n | 0xffffffff) > end) {
            e = end & 0xffffffff;

        } else {
            e = 0xffffffff;
        }

        a = (ngx_array_t *) ctx->high.low[h];

        if (a == NULL) {
            a = ngx_array_create(ctx->temp_pool, 128,
                                 sizeof(ngx_http_lookup_t));
            if (a == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->high.low[h] = (ngx_http_lookup_t *) a;
        }

        i = a->nelts;
        range = a->elts;

        while (i) {

            i--;

            if (e < range[i].start) {
                continue;
            }

            if (s > range[i].end) {

                /* add after the range */

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = a->elts;

                ngx_memmove(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(ngx_http_lookup_t));

                range[i + 1].start = (ngx_int_t) s;
                range[i + 1].end = (ngx_int_t) e;
                range[i + 1].value = ctx->value;

                goto next;
            }

            if (s == range[i].start
                && e == range[i].end)
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
                    ctx->net, ctx->value, range[i].value);

                range[i].value = ctx->value;

                goto next;
            }

            if (s > range[i].start
                && e < range[i].end)
            {
                /* split the range and insert the new one */

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = a->elts;

                ngx_memmove(&range[i + 3], &range[i + 1],
                           (a->nelts - 3 - i) * sizeof(ngx_http_lookup_t));

                range[i + 2].start = (ngx_int_t) (e + 1);
                range[i + 2].end = range[i].end;
                range[i + 2].value = range[i].value;

                range[i + 1].start = (ngx_int_t) s;
                range[i + 1].end = (ngx_int_t) e;
                range[i + 1].value = ctx->value;

                range[i].end = (ngx_int_t) (s - 1);

                goto next;
            }

            if (s == range[i].start
                && e < range[i].end)
            {
                /* shift the range start and insert the new range */

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = a->elts;

                ngx_memmove(&range[i + 1], &range[i],
                           (a->nelts - 1 - i) * sizeof(ngx_http_lookup_t));

                range[i + 1].start = (ngx_int_t) (e + 1);

                range[i].start = (ngx_int_t) s;
                range[i].end = (ngx_int_t) e;
                range[i].value = ctx->value;

                goto next;
            }

            if (s > range[i].start
                && e == range[i].end)
            {
                /* shift the range end and insert the new range */

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = a->elts;

                ngx_memmove(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(ngx_http_lookup_t));

                range[i + 1].start = (ngx_int_t) s;
                range[i + 1].end = (ngx_int_t) e;
                range[i + 1].value = ctx->value;

                range[i].end = (ngx_int_t) (s - 1);

                goto next;
            }

            s = (ngx_uint_t) range[i].start;
            e = (ngx_uint_t) range[i].end;

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "lookup \"%V\" overlaps \"%ui-%ui\"",
                         ctx->net, (h << 32) | s, (h << 32) | e);

            return NGX_CONF_ERROR;
        }

        /* add the first range */

        range = ngx_array_push(a);
        if (range == NULL) {
            return NGX_CONF_ERROR;
        }

        range->start = (ngx_int_t) s;
        range->end = (ngx_int_t) e;
        range->value = ctx->value;

    next:

        continue;
    }

    return NGX_CONF_OK;
}



static ngx_http_variable_value_t *
ngx_http_lookup_value(ngx_conf_t *cf, ngx_http_lookup_conf_ctx_t *ctx,
    ngx_str_t *value)
{
    uint32_t                             hash;
    ngx_http_variable_value_t           *val;
    ngx_http_lookup_variable_value_node_t  *gvvn;

    hash = ngx_crc32_long(value->data, value->len);

    gvvn = (ngx_http_lookup_variable_value_node_t *)
               ngx_str_rbtree_lookup(&ctx->rbtree, value, hash);

    if (gvvn) {
        return gvvn->value;
    }

    val = ngx_palloc(ctx->pool, sizeof(ngx_http_variable_value_t));
    if (val == NULL) {
        return NULL;
    }

    val->len = value->len;
    val->data = ngx_pstrdup(ctx->pool, value);
    if (val->data == NULL) {
        return NULL;
    }

    val->valid = 1;
    val->no_cacheable = 0;
    val->not_found = 0;

    gvvn = ngx_palloc(ctx->temp_pool,
                      sizeof(ngx_http_lookup_variable_value_node_t));
    if (gvvn == NULL) {
        return NULL;
    }

    gvvn->sn.node.key = hash;
    gvvn->sn.str.len = val->len;
    gvvn->sn.str.data = val->data;
    gvvn->value = val;
    gvvn->offset = 0;

    ngx_rbtree_insert(&ctx->rbtree, &gvvn->sn.node);

    ctx->data_size += ngx_align(sizeof(ngx_http_variable_value_t) + value->len,
                                sizeof(void *));

    return val;
}



static char *
ngx_http_lookup_include(ngx_conf_t *cf, ngx_http_lookup_conf_ctx_t *ctx,
    ngx_str_t *name)
{
    char       *rv;
    ngx_str_t   file;

    file.len = name->len + 4;
    file.data = ngx_pnalloc(ctx->temp_pool, name->len + 5);
    if (file.data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_sprintf(file.data, "%V.bin%Z", name);

    if (ngx_conf_full_name(cf->cycle, &file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ctx->ranges) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        switch (ngx_http_lookup_include_binary_base(cf, ctx, &file)) {
        case NGX_OK:
            return NGX_CONF_OK;
        case NGX_ERROR:
            return NGX_CONF_ERROR;
        default:
            break;
        }
    }

    file.len -= 4;
    file.data[file.len] = '\0';

    ctx->include_name = file;

    if (ctx->outside_entries) {
        ctx->allow_binary_include = 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

    rv = ngx_conf_parse(cf, &file);

    ctx->includes++;
    ctx->outside_entries = 0;

    return rv;
}


static ngx_int_t
ngx_http_lookup_include_binary_base(ngx_conf_t *cf, ngx_http_lookup_conf_ctx_t *ctx,
    ngx_str_t *name)
{
    u_char                     *base, ch;
    time_t                      mtime;
    size_t                      size, len;
    ssize_t                     n;
    uint32_t                    crc32;
    ngx_err_t                   err;
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_file_t                  file;
    ngx_file_info_t             fi;
    ngx_http_lookup_t       *range, **ranges;
    ngx_http_lookup_header_t      *header;
    ngx_http_variable_value_t  *vv;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = *name;
    file.log = cf->log;

    file.fd = ngx_open_file(name->data, NGX_FILE_RDONLY, 0, 0);
    if (file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        if (err != NGX_ENOENT) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, err,
                               ngx_open_file_n " \"%s\" failed", name->data);
        }
        return NGX_DECLINED;
    }

    if (ctx->outside_entries) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "binary lookup range base \"%s\" cannot be mixed with usual entries",
            name->data);
        rc = NGX_ERROR;
        goto done;
    }

    if (ctx->binary_include) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "second binary lookup range base \"%s\" cannot be mixed with \"%s\"",
            name->data, ctx->include_name.data);
        rc = NGX_ERROR;
        goto done;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_fd_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    size = (size_t) ngx_file_size(&fi);
    mtime = ngx_file_mtime(&fi);

    ch = name->data[name->len - 4];
    name->data[name->len - 4] = '\0';

    if (ngx_file_info(name->data, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_file_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    name->data[name->len - 4] = ch;

    if (mtime < ngx_file_mtime(&fi)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "stale binary lookup range base \"%s\"", name->data);
        goto failed;
    }

    base = ngx_palloc(ctx->pool, size);
    if (base == NULL) {
        goto failed;
    }

    n = ngx_read_file(&file, base, size, 0);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" failed", name->data);
        goto failed;
    }

    if ((size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
            ngx_read_file_n " \"%s\" returned only %z bytes instead of %z",
            name->data, n, size);
        goto failed;
    }

    header = (ngx_http_lookup_header_t *) base;

    if (size < 16 || ngx_memcmp(&ngx_http_lookup_header, header, 12) != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
             "incompatible binary lookup range base \"%s\"", name->data);
        goto failed;
    }

    ngx_crc32_init(crc32);

    vv = (ngx_http_variable_value_t *) (base + sizeof(ngx_http_lookup_header_t));

    while(vv->data) {
        len = ngx_align(sizeof(ngx_http_variable_value_t) + vv->len,
                        sizeof(void *));
        ngx_crc32_update(&crc32, (u_char *) vv, len);
        vv->data += (size_t) base;
        vv = (ngx_http_variable_value_t *) ((u_char *) vv + len);
    }
    ngx_crc32_update(&crc32, (u_char *) vv, sizeof(ngx_http_variable_value_t));
    vv++;

    ranges = (ngx_http_lookup_t **) vv;

    for (i = 0; i < 0x10000; i++) {
        ngx_crc32_update(&crc32, (u_char *) &ranges[i], sizeof(void *));
        if (ranges[i]) {
            ranges[i] = (ngx_http_lookup_t *)
                            ((u_char *) ranges[i] + (size_t) base);
        }
    }

    range = (ngx_http_lookup_t *) &ranges[0x10000];

    while ((u_char *) range < base + size) {
        while (range->value) {
            ngx_crc32_update(&crc32, (u_char *) range,
                             sizeof(ngx_http_lookup_t));
            range->value = (ngx_http_variable_value_t *)
                               ((u_char *) range->value + (size_t) base);
            range++;
        }
        ngx_crc32_update(&crc32, (u_char *) range, sizeof(void *));
        range = (ngx_http_lookup_t *) ((u_char *) range + sizeof(void *));
    }

    ngx_crc32_final(crc32);

    if (crc32 != header->crc32) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                  "CRC32 mismatch in binary lookup range base \"%s\"", name->data);
        goto failed;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "using binary lookup range base \"%s\"", name->data);

    ctx->include_name = *name;
    ctx->binary_include = 1;
    ctx->high.low = ranges;
    rc = NGX_OK;

    goto done;

failed:

    rc = NGX_DECLINED;

done:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", name->data);
    }

    return rc;
}


static void
ngx_http_lookup_create_binary_base(ngx_http_lookup_conf_ctx_t *ctx)
{
    u_char                              *p;
    uint32_t                             hash;
    ngx_str_t                            s;
    ngx_uint_t                           i;
    ngx_file_mapping_t                   fm;
    ngx_http_lookup_t                *r, *range, **ranges;
    ngx_http_lookup_header_t               *header;
    ngx_http_lookup_variable_value_node_t  *gvvn;

    fm.name = ngx_pnalloc(ctx->temp_pool, ctx->include_name.len + 5);
    if (fm.name == NULL) {
        return;
    }

    ngx_sprintf(fm.name, "%V.bin%Z", &ctx->include_name);

    fm.size = ctx->data_size;
    fm.log = ctx->pool->log;

    ngx_log_error(NGX_LOG_NOTICE, fm.log, 0,
                  "creating binary lookup range base \"%s\"", fm.name);

    if (ngx_create_file_mapping(&fm) != NGX_OK) {
        return;
    }

    p = ngx_cpymem(fm.addr, &ngx_http_lookup_header,
                   sizeof(ngx_http_lookup_header_t));

    p = ngx_http_lookup_copy_values(fm.addr, p, ctx->rbtree.root,
                                 ctx->rbtree.sentinel);

    p += sizeof(ngx_http_variable_value_t);

    ranges = (ngx_http_lookup_t **) p;

    p += 0x10000 * sizeof(ngx_http_lookup_t *);

    for (i = 0; i < 0x10000; i++) {
        r = ctx->high.low[i];
        if (r == NULL) {
            continue;
        }

        range = (ngx_http_lookup_t *) p;
        ranges[i] = (ngx_http_lookup_t *) (p - (u_char *) fm.addr);

        do {
            s.len = r->value->len;
            s.data = r->value->data;
            hash = ngx_crc32_long(s.data, s.len);
            gvvn = (ngx_http_lookup_variable_value_node_t *)
                        ngx_str_rbtree_lookup(&ctx->rbtree, &s, hash);

            range->value = (ngx_http_variable_value_t *) gvvn->offset;
            range->start = r->start;
            range->end = r->end;
            range++;

        } while ((++r)->value);

        range->value = NULL;

        p = (u_char *) range + sizeof(void *);
    }

    header = fm.addr;
    header->crc32 = ngx_crc32_long((u_char *) fm.addr
                                       + sizeof(ngx_http_lookup_header_t),
                                   fm.size - sizeof(ngx_http_lookup_header_t));

    ngx_close_file_mapping(&fm);
}


static u_char *
ngx_http_lookup_copy_values(u_char *base, u_char *p, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_http_variable_value_t           *vv;
    ngx_http_lookup_variable_value_node_t  *gvvn;

    if (node == sentinel) {
        return p;
    }

    gvvn = (ngx_http_lookup_variable_value_node_t *) node;
    gvvn->offset = p - base;

    vv = (ngx_http_variable_value_t *) p;
    *vv = *gvvn->value;
    p += sizeof(ngx_http_variable_value_t);
    vv->data = (u_char *) (p - base);

    p = ngx_cpymem(p, gvvn->sn.str.data, gvvn->sn.str.len);

    p = ngx_align_ptr(p, sizeof(void *));

    p = ngx_http_lookup_copy_values(base, p, node->left, sentinel);

    return ngx_http_lookup_copy_values(base, p, node->right, sentinel);
}
