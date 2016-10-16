#include <stdbool.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

// Module structures

typedef struct {
  ngx_flag_t issue;
  jwt_alg_t algorithm;
} ngx_http_jwt_loc_conf_t;

typedef struct {
} ngx_http_jwt_ctx_t;

// Function forward declaration

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf,
                                         void *parent,
                                         void *child);
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf);
// jwt_issue functions
static char *ngx_http_jwt_issue(ngx_conf_t *cf,
                                ngx_command_t *cmd,
                                void *conf);
static ngx_int_t ngx_http_jwt_issue_header_filter(ngx_http_request_t *request);
static ngx_int_t ngx_http_jwt_issue_body_filter(ngx_http_request_t *request,
                                                ngx_chain_t *chain);

// Directives
static ngx_command_t ngx_http_jwt_commands[] = {
  { ngx_string("jwt_issue"),
    NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_http_jwt_issue,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_jwt_loc_conf_t, issue),
    NULL },
  ngx_null_command
};

// Module definition

static ngx_http_module_t ngx_http_jwt_module_ctx = {
  NULL,                                  /* preconfiguration */
  ngx_http_jwt_init,                     /* postconfiguration */

  NULL,                                  /* create main configuration */
  NULL,                                  /* init main configuration */

  NULL,                                  /* create server configuration */
  NULL,                                  /* merge server configuration */

  ngx_http_jwt_create_loc_conf,          /* create location configuration */
  ngx_http_jwt_merge_loc_conf            /* merge location configuration */
};

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

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

// Function implementation

// Create location configuration
static void * ngx_http_jwt_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_jwt_loc_conf_t  *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }
  conf->issue = NGX_CONF_UNSET;

  return conf;
}

// Merge location configuration
static char * ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_jwt_loc_conf_t *prev = parent;
  ngx_http_jwt_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->issue, prev->issue, false);

  return NGX_CONF_OK;
}

// jwt_issue directive
static char * ngx_http_jwt_issue(ngx_conf_t *cf, ngx_command_t *cmd, void *hint) {
  return ngx_conf_set_flag_slot(cf, cmd, hint);
}

static ngx_int_t ngx_http_jwt_issue_header_filter(ngx_http_request_t *r) {
  ngx_http_jwt_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);
  if (!conf->issue) {
    return ngx_http_next_header_filter(r);
  }

  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_issue_header_filter");

  return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_jwt_issue_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
  ngx_http_jwt_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);
  if (!conf->issue) {
    return ngx_http_next_body_filter(r, in);
  }

  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_issue_body_filter");

  for (ngx_chain_t *cl = in; cl; cl = cl->next) {
    size_t len = cl->buf->last - cl->buf->pos;
    if (len > 0) {
      // TODO(SN): use buffer directly to parse json (jansson: json_loadb)
      char *body = ngx_pcalloc(r->pool, len);
      memcpy(body, cl->buf->pos, len);
      ngx_log_stderr(0, "buf: %s", body);
      // TODO(SN): concatenate buffers before creating token?
      jwt_t* token;
      if (jwt_new(&token) < 0) {
        // TODO(SN): log error
        return NGX_ERROR;
      }
      // TODO(SN): allow to switch JWT algorithm via directive / argument
      // TODO(SN): load key material from directive argument (file)
      char *key = "secretsecretsecretsecretsecret??";
      if (jwt_set_alg(token, JWT_ALG_HS256, (unsigned char *)key, 32) < 0) {
        // TODO(SN): log error
        return ngx_http_next_body_filter(r, in);
      }
      if (jwt_add_grants_json(token, body) < 0) {
        // TODO(SN): log error
        return ngx_http_next_body_filter(r, in);
      }
      // Write token to a single buffer
      char *d = jwt_encode_str(token);
      size_t dlen = strlen(d);
      ngx_log_stderr(0, "token: (%d) %s", dlen, d);
      ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
      if (out == NULL) {
        return NGX_ERROR;
      }
      ngx_buf_t *buf = ngx_alloc_buf(r->pool);
      if (buf == NULL) {
        return NGX_ERROR;
      }
      buf->pos = buf->start = (unsigned char *)d;
      buf->last = buf->end = (unsigned char *)d + dlen;
      buf->memory = true;
      buf->last_buf = true;
      out->buf = buf;
      out->next = NULL;
      return ngx_http_next_body_filter(r, out);
    }
  }

  return ngx_http_next_body_filter(r, in);
}

// Post configuration - add request handler
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf) {
  // Install jwt_issue_filter
  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_jwt_issue_header_filter;

  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_jwt_issue_body_filter;

  return NGX_OK;
}
