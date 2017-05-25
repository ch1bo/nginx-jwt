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
  ngx_flag_t verify;
} ngx_http_jwt_conf_t;

// TODO(SN): make this configurable - use client_body_buffer_size or own directive?
# define NGX_JWT_BODY_BUFFER_SIZE 1048576  // 1m - default client_max_body_size

typedef struct {
  char body_buffer[NGX_JWT_BODY_BUFFER_SIZE];
  ngx_uint_t body_buffer_pos;
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
  conf->verify = NGX_CONF_UNSET;

  return conf;
}

// Merge location configuration
static char * ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_jwt_conf_t *prev = parent;
  ngx_http_jwt_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->key, prev->key, "");
  ngx_conf_merge_value(conf->issue, prev->issue, false);
  ngx_conf_merge_uint_value(conf->issue_algorithm, prev->issue_algorithm, JWT_ALG_NONE);
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
  ngx_http_jwt_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);
  if (!conf->issue) {
    return ngx_http_next_header_filter(r);
  }
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_issue_header_filter");

  ngx_http_jwt_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_jwt_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_jwt_ctx_t));
    if (ctx == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                    "jwt_issue: error creating context");
      return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_jwt_module);
  }
  bzero(ctx->body_buffer, NGX_JWT_BODY_BUFFER_SIZE);
  ctx->body_buffer_pos = 0;

  // chunked encoding and connection close
  ngx_http_clear_content_length(r);
  r->keepalive = false;
  return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_jwt_issue_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
  ngx_http_jwt_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);
  if (!conf->issue) {
    return ngx_http_next_body_filter(r, in);
  }
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_issue_body_filter");

  ngx_http_jwt_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_jwt_module);
  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_issue: context should exist");
    return NGX_ERROR;
  }

  // Collect all chain buffers in context body buffer
  size_t len;
  ngx_chain_t *cl;
  for (cl = in; cl; cl = cl->next) {
    len = ngx_buf_size(cl->buf);
    if (len > 0) {
      if (ctx->body_buffer_pos + len > NGX_JWT_BODY_BUFFER_SIZE - 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "jwt_issue: cannot issue token from too large body, max is %O bytes",
                      NGX_JWT_BODY_BUFFER_SIZE);
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
      }
      memcpy(ctx->body_buffer + ctx->body_buffer_pos, cl->buf->pos, len);
      ctx->body_buffer_pos += len;
      ngx_log_stderr(0, "buffering %d bytes", len);
    }
    if (cl->buf->last_buf && ctx->body_buffer_pos > 0) {
      // TODO(SN): use buffer directly to parse json (jansson: json_loadb)
      // instead of requiring null terminated string in jwt_add_grants_json
      ctx->body_buffer[ctx->body_buffer_pos] = '\0';
      ngx_log_stderr(0, "body buffer: (%d) %s", ctx->body_buffer_pos, ctx->body_buffer);
      ctx->body_buffer_pos = 0;
      // Create token from body buffer
      jwt_t* token;
      int err = jwt_new(&token);
      if (err) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "jwt_issue jwt_new: %s", strerror(errno));
        return NGX_ERROR;
      }
      err = jwt_set_alg(token, conf->issue_algorithm, conf->key.data, conf->key.len);
      if (err) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "jwt_issue jwt_set_alg: %s", strerror(errno));
        return ngx_http_next_body_filter(r, in);
      }
      err = jwt_add_grants_json(token, ctx->body_buffer);
      if (err) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "jwt_issue jwt_add_grants: %s", strerror(errno));
        return ngx_http_next_body_filter(r, in);
      }

      // TODO(SN): issue ttl
      // Write token to a single buffer
      // TODO(SN): buffer writing broken
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
      // TODO(SN): recv() failed error?
      // nginx-jwt_1  | 2017/05/25 15:59:25 [info] 7#0: *3 recv() failed (104: Connection reset by peer) while sending to client, client: 172.19.0.4, server: , request: "POST /login HTTP/1.1", upstream: "http://172.19.0.2:80/login", host: "nginx-jwt"
      return ngx_http_next_body_filter(r, out);
    }
  }
  return NGX_OK;
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
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: alg=\"none\" rejected");
    return NGX_HTTP_UNAUTHORIZED;
  }
  // TODO(SN): verify ttl
  // Extract payload and modify header
  char *token_str = jwt_dump_str(token, false);
  char *payload = ngx_strstr(token_str, ".");
  if (payload == NULL || payload + 1 >= payload + strlen(payload)) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: no '.' in token");
    return NGX_HTTP_UNAUTHORIZED;
  }
  payload++;
  ngx_log_stderr(0, "payload: %s", payload);
  ngx_table_elt_t *header = ngx_list_push(&r->headers_out.headers);
  if (header == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: error creating header");
    return NGX_HTTP_UNAUTHORIZED;
  }
  header->hash = 1;
  ngx_str_set(&header->key, "authorization");
  ngx_str_set(&header->value, payload);
  return NGX_OK;
}
