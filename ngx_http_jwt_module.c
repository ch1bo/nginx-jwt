#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// Module structures

typedef struct {
  ngx_str_t uri;
  ngx_array_t *vars;
} ngx_http_jwt_loc_conf_t;

typedef struct {
  ngx_uint_t done;
  ngx_uint_t status;
  ngx_http_request_t *subrequest;
} ngx_http_jwt_ctx_t;

typedef struct {
  ngx_int_t                 index;
  ngx_http_complex_value_t  value;
  ngx_http_set_variable_pt  set_handler;
} ngx_http_auth_request_variable_t;

// Function forward declaration

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf,
                                         void *parent,
                                         void *child);
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf);
static char *ngx_http_jwt_request(ngx_conf_t *cf,
                                  ngx_command_t *cmd,
                                  void *conf);
static ngx_int_t ngx_http_jwt_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_jwt_request_done(ngx_http_request_t *r,
                                           void *data,
                                           ngx_int_t rc);

// Directives
static ngx_command_t ngx_http_jwt_commands[] = {
  { ngx_string("jwt_request"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_jwt_request,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  ngx_null_command
};

// Context creation functions
static ngx_http_module_t ngx_http_jwt_module_ctx = {
  NULL,                                  /* preconfiguration */
  ngx_http_jwt_init,            /* postconfiguration */

  NULL,                                  /* create main configuration */
  NULL,                                  /* init main configuration */

  NULL,                                  /* create server configuration */
  NULL,                                  /* merge server configuration */

  ngx_http_jwt_create_loc_conf,          /* create location configuration */
  ngx_http_jwt_merge_loc_conf            /* merge location configuration */
};

// Module description
ngx_module_t  ngx_http_jwt_module = {
  NGX_MODULE_V1,
  &ngx_http_jwt_module_ctx,              /* module context */
  ngx_http_jwt_commands,                 /* module directives */
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

// Function implementation

// Create location configuration
static void * ngx_http_jwt_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_jwt_loc_conf_t  *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  // set by ngx_pcalloc():
  // conf->uri = { 0, NULL };
  conf->vars = NGX_CONF_UNSET_PTR;

  return conf;
}

// Merge location configuration
static char * ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_jwt_loc_conf_t *prev = parent;
  ngx_http_jwt_loc_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->uri, prev->uri, "");
  ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

  return NGX_CONF_OK;
}

// 'jwt_request' directive
static char * ngx_http_jwt_request(ngx_conf_t *cf, ngx_command_t *cmd, void *hint) {
  ngx_http_jwt_loc_conf_t *conf = hint;
  ngx_str_t *value;

  ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "jwt_request directive");

  if (conf->uri.data != NULL) {
    return "is duplicate";
  }

  value = cf->args->elts;

  if (ngx_strcmp(value[1].data, "off") == 0) {
    conf->uri.len = 0;
    conf->uri.data = (u_char *) "";

    return NGX_CONF_OK;
  }

  conf->uri = value[1];

  return NGX_CONF_OK;
}

// Post configuration - add request handler
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf) {
  ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_jwt_request_handler;

  return NGX_OK;
}

static ngx_int_t ngx_http_jwt_request_handler(ngx_http_request_t *r) {
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_handler");

  ngx_http_jwt_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);

  if (conf->uri.len == 0) {
    return NGX_DECLINED;
  }

  ngx_http_jwt_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_jwt_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_jwt_ctx_t));
    if (ctx == NULL) {
      return NGX_ERROR;
    }

    // TODO(SN): let this proxy instead of a new subrequest
    ngx_http_post_subrequest_t *ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
      return NGX_ERROR;
    }
    ps->handler = ngx_http_jwt_request_done;
    ps->data = ctx;

    ngx_http_request_t *sr;
    if (ngx_http_subrequest(r, &conf->uri, NULL, &sr, ps, NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK) {
      return NGX_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "jwt_handler subrequest: %s", conf-uri);

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */
    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
      return NGX_ERROR;
    }
    sr->header_only = 1;

    ctx->subrequest = sr;
    ngx_http_set_ctx(r, ctx, ngx_http_jwt_module);
  } else if (ctx->done) { // Subrequest finished
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "jwt_handler subrequest done:%ui", ctx->status);

    /* return appropriate status */

    if (ctx->status == NGX_HTTP_FORBIDDEN) {
      return ctx->status;
    }

    if (ctx->status == NGX_HTTP_UNAUTHORIZED) {
      ngx_http_request_t *sr = ctx->subrequest;

      ngx_table_elt_t *h = sr->headers_out.www_authenticate;
      if (!h && sr->upstream) {
        h = sr->upstream->headers_in.www_authenticate;
      }

      if (h) {
        ngx_table_elt_t *ho = ngx_list_push(&r->headers_out.headers);
        if (ho == NULL) {
          return NGX_ERROR;
        }

        *ho = *h;

        r->headers_out.www_authenticate = ho;
      }

      return ctx->status;
    }

    if (ctx->status >= NGX_HTTP_OK
        && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
      {
        return NGX_OK;
      }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "auth request unexpected status: %ui", ctx->status);

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  return NGX_AGAIN;
}


static ngx_int_t ngx_http_jwt_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc) {
  ngx_http_jwt_ctx_t *ctx = data;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "jwt_request_done: %ui", r->headers_out.status);

  ctx->done = 1;
  ctx->status = r->headers_out.status;
  return rc;
}
