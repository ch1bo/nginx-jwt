#include <stdbool.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

// Module structures

typedef struct {
  ngx_str_t key;
  ngx_flag_t issue;
  ngx_uint_t issue_algorithm;
  size_t issue_buffer_size;
  ngx_flag_t verify;
} ngx_http_jwt_conf_t;

typedef struct {
  size_t length;
  unsigned char *body;
  unsigned char *last;
} ngx_http_jwt_ctx_t;

// Function forward declaration

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf,
                                         void *parent,
                                         void *child);
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_jwt_issue_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_jwt_issue_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_jwt_verify_handler(ngx_http_request_t *r);

static ngx_conf_enum_t ngx_http_jwt_algorithms[] = {
  { ngx_string("none"), JWT_ALG_NONE },
  { ngx_string("HS256"), JWT_ALG_HS256 },
  { ngx_string("HS384"), JWT_ALG_HS384 },
  { ngx_string("HS512"), JWT_ALG_HS512 },
  { ngx_string("RS256"), JWT_ALG_RS256 },
  { ngx_string("RS384"), JWT_ALG_RS384 },
  { ngx_string("RS512"), JWT_ALG_RS512 },
  { ngx_string("ES256"), JWT_ALG_ES256 },
  { ngx_string("ES384"), JWT_ALG_ES384 },
  { ngx_string("ES512"), JWT_ALG_ES512 },
  { ngx_null_string, 0 }
};

// Directives
static ngx_command_t ngx_http_jwt_commands[] = {
  { ngx_string("jwt_key"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_jwt_conf_t, key),
    NULL },
  { ngx_string("jwt_issue"),
    NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_jwt_conf_t, issue),
    NULL },
  { ngx_string("jwt_issue_algorithm"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_enum_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_jwt_conf_t, issue_algorithm),
    &ngx_http_jwt_algorithms },
  { ngx_string("jwt_issue_buffer_size"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_jwt_conf_t, issue_buffer_size),
    NULL },
  { ngx_string("jwt_verify"),
    NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_jwt_conf_t, verify),
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
  ngx_http_jwt_conf_t  *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_conf_t));
  if (conf == NULL) {
    return NULL;
  }
  conf->issue = NGX_CONF_UNSET;
  conf->issue_algorithm = NGX_CONF_UNSET_UINT;
  conf->issue_buffer_size = NGX_CONF_UNSET_SIZE;
  conf->verify = NGX_CONF_UNSET;

  return conf;
}

// Merge location configuration
static char * ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_jwt_conf_t *prev = parent;
  ngx_http_jwt_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->key, prev->key, "");
  ngx_conf_merge_value(conf->issue, prev->issue, false);
  ngx_conf_merge_uint_value(conf->issue_algorithm, prev->issue_algorithm, JWT_ALG_HS512);
  ngx_conf_merge_size_value(conf->issue_buffer_size, prev->issue_buffer_size,
                            1 * 1024 * 1024);
  ngx_conf_merge_value(conf->verify, prev->verify, false);

  return NGX_CONF_OK;
}

// Post configuration - add request handler
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf) {
  // Install jwt_issue filters
  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_jwt_issue_header_filter;
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_jwt_issue_body_filter;

  // Install jwt_verify handler
  ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_jwt_verify_handler;
  return NGX_OK;
}

static ngx_int_t ngx_http_jwt_issue_header_filter(ngx_http_request_t *r) {
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_issue_header_filter");

  ngx_http_jwt_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);
  if (!conf->issue) {
    return ngx_http_next_header_filter(r);
  }

  off_t len = r->headers_out.content_length_n;
  ngx_log_stderr(0, "header: content length %d -> %d", r->headers_in.content_length_n, len);
  if (len > 0 && len > (off_t)conf->issue_buffer_size) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "jwt_issue: cannot issue token from too large body, max is %O bytes",
                  conf->issue_buffer_size);
    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
  }

  ngx_http_jwt_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_jwt_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_jwt_ctx_t));
    if (ctx == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                    "jwt_issue: error creating context");
      return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_jwt_module);
  } else {
    ngx_log_stderr(0, "ctx already initialized!!");
  }

  // content_length_n == -1 means chunked encoding
  if (len == -1) {
    ctx->length = conf->issue_buffer_size;
  } else {
    ctx->length = (size_t)len + 1; // TODO(SN): no 0-termination
  }
  // skip all other header filters (for now)
  return NGX_OK;
}

static ngx_int_t ngx_http_jwt_issue_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_issue_body_filter");

  ngx_log_stderr(0, "request status %d", r->headers_out.status);

  ngx_http_jwt_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);
  if (!conf->issue || in == NULL || r->headers_out.status != NGX_HTTP_OK) {
    ngx_int_t rc = ngx_http_next_header_filter(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
      return NGX_ERROR;
    }
    return ngx_http_next_body_filter(r, in);
  }

  ngx_http_jwt_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_jwt_module);
  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_issue: context could not be retrieved");
    return NGX_ERROR;
  }

  // Collect all chain buffers in context
  if (ctx->body == NULL) {
    ctx->body = ngx_palloc(r->pool, ctx->length);
    if (ctx->body == NULL) {
      return NGX_ERROR;
    }
    ctx->last = ctx->body;
  }
  size_t size;
  ngx_chain_t *cl;
  ngx_buf_t *b = NULL;
  for (cl = in; cl; cl = cl->next) {
    b = cl->buf;
    size = ngx_buf_size(b);
    size_t pos = ctx->last - ctx->body;
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "jwt buf: %uz / %uz + %uz", pos, ctx->length, size);
    if (pos + size > ctx->length - 1) { // TODO(SN): no 0-termination
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "jwt_issue: cannot issue token from too large body, max is %O bytes",
                    conf->issue_buffer_size);
      return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    ctx->last = ngx_cpymem(ctx->last, b->pos, size);
    b->pos += size;
  }
  if (b && !b->last_buf) {
    /* TODO required? r->connection->buffered |= NGX_HTTP_IMAGE_BUFFERED; */
    return NGX_OK;
  }
  /* TODO required? r->connection->buffered &= ~NGX_HTTP_IMAGE_BUFFERED; */

  // Create token from body buffer
  jwt_t* token;
  int err = jwt_new(&token); // TODO(SN): memory leak
  if (err) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_issue jwt_new: %s", strerror(errno));
    return NGX_ERROR;
  }

  err = jwt_set_alg(token, conf->issue_algorithm, conf->key.data, conf->key.len);
  if (err) {
    jwt_free(token);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_issue jwt_set_alg: %s", strerror(errno));
    return NGX_ERROR;
  }
  // TODO(SN): use buffer directly to parse json (jansson: json_loadb)
  // instead of requiring null terminated string in jwt_add_grants_json
  *(ctx->last) = '\0';
  ngx_log_stderr(0, "body buffer: (%d/%d) %s", ctx->last - ctx->body, ctx->length, ctx->body);
  err = jwt_add_grants_json(token, (char *)ctx->body);
  if (err) {
    jwt_free(token);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_issue jwt_add_grants: %s", strerror(errno));
    return NGX_ERROR;
  }
  // TODO(SN): issue ttl
  // Write token to a single buffer and update headers
  char *token_data = jwt_encode_str(token); // TODO(SN): this leaks
  jwt_free(token);
  if (token_data == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_issue jwt_encode_str: %s", strerror(errno));
    return NGX_ERROR;
  }
  ngx_pool_cleanup_t *cleanup = ngx_pool_cleanup_add(r->pool, 0);
  if (cleanup == NULL) {
    return NGX_ERROR;
  }
  cleanup->handler = free;
  cleanup->data = token_data;
  size_t token_size = strlen(token_data);
  ngx_log_stderr(0, "token: (%d) %s", token_size, token_data);
  ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
  if (out == NULL) {
    return NGX_ERROR;
  }
  ngx_buf_t *buf = ngx_calloc_buf(r->pool);
  if (buf == NULL) {
    return NGX_ERROR;
  }
  buf->pos = buf->start = (unsigned char*) token_data;
  buf->last = buf->end = (unsigned char*) token_data + token_size;
  buf->memory = true; // buffer is in read-only memory
  buf->last_buf = true;
  out->buf = buf;
  out->next = NULL;
  r->headers_out.content_length_n = token_size;

  ngx_int_t rc = ngx_http_next_header_filter(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return NGX_ERROR;
  }
  return ngx_http_next_body_filter(r, out);
}

ngx_int_t ngx_http_jwt_verify_handler(ngx_http_request_t *r) {
  ngx_http_jwt_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);
  if (!conf->verify) {
    return NGX_OK;
  }
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_verify_handler");

  if (conf->key.len == 0) {
    ngx_log_stderr(0, "jwt_verify: missing 'jwt_key'");
    return NGX_ERROR;
  }

  if (!r->headers_in.authorization) {
    return NGX_HTTP_UNAUTHORIZED;
  }
  ngx_log_stderr(0, "auth: %s", r->headers_in.authorization->value.data);

  jwt_t* token;
  int err = jwt_decode(&token, (const char *)r->headers_in.authorization->value.data,
                       conf->key.data, conf->key.len);
  if (err) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: error on decode: %s", strerror(errno));
    return NGX_HTTP_UNAUTHORIZED;
  }
  if (jwt_get_alg(token) == JWT_ALG_NONE) {
    jwt_free(token);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: alg=\"none\" rejected");
    return NGX_HTTP_UNAUTHORIZED;
  }
  // TODO(SN): verify ttl
  // Extract grants and modify header
  char *grants = jwt_get_grants_json(token, NULL);
  jwt_free(token);
  if (grants == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: error on jwt_dump_str: %s", strerror(errno));
    return NGX_HTTP_UNAUTHORIZED;
  }
  ngx_pool_cleanup_t *cleanup = ngx_pool_cleanup_add(r->pool, 0);
  if (cleanup == NULL) {
    free(grants);
    return NGX_ERROR;
  }
  cleanup->handler = free;
  cleanup->data = grants;
  ngx_log_stderr(0, "grants: %s", grants);
  ngx_table_elt_t *header = ngx_list_push(&r->headers_out.headers);
  if (header == NULL) {
    free(grants);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: error creating header");
    return NGX_HTTP_UNAUTHORIZED;
  }
  header->hash = 1;
  ngx_str_set(&header->key, "authorization");
  ngx_str_set(&header->value, grants);
  return NGX_OK;
}
