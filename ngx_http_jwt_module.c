#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdbool.h>

// Module structures

typedef struct {
  ngx_str_t uri;
  ngx_flag_t jwt_issue;
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
// jwt_request functions
static char *ngx_http_jwt_request(ngx_conf_t *cf,
                                  ngx_command_t *cmd,
                                  void *conf);
// jwt_issue functions
static char *ngx_http_jwt_issue(ngx_conf_t *cf,
                                ngx_command_t *cmd,
                                void *conf);
static ngx_int_t ngx_http_jwt_issue_filter(ngx_http_request_t *request,
                                           ngx_chain_t *chain);

// Directives
static ngx_command_t ngx_http_jwt_commands[] = {
  { ngx_string("jwt_request"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_jwt_request,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("jwt_issue"),
    NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
    ngx_http_jwt_issue,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
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

static ngx_http_request_body_filter_pt ngx_http_next_request_body_filter;

// Function implementation

// Create location configuration
static void * ngx_http_jwt_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_jwt_loc_conf_t  *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  return conf;
}

// Merge location configuration
static char * ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_jwt_loc_conf_t *prev = parent;
  ngx_http_jwt_loc_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->uri, prev->uri, "");
  ngx_conf_merge_value(conf->jwt_issue, prev->jwt_issue, false);

  return NGX_CONF_OK;
}

// jwt_request directive
static char * ngx_http_jwt_request(ngx_conf_t *cf, ngx_command_t *cmd, void *hint) {
  ngx_http_jwt_loc_conf_t *conf = hint;
  ngx_str_t *value;

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

// jwt_issue directive
static char * ngx_http_jwt_issue(ngx_conf_t *cf, ngx_command_t *cmd, void *hint) {
  ngx_http_jwt_loc_conf_t *conf = hint;
  conf->jwt_issue = true;
  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_jwt_issue_filter(ngx_http_request_t *r, ngx_chain_t *in) {
  ngx_http_jwt_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);
  if (!conf->jwt_issue) {
    return ngx_http_next_request_body_filter(r, in);
  }
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "jwt_issue_filter enabled");
  for (ngx_chain_t *cl = in; cl; cl = cl->next) {
    size_t len = cl->buf->last - cl->buf->pos;
    char body[len];
    memcpy(body, cl->buf->pos, len);
    ngx_log_stderr(0, "%s\n", body);
  }

  return ngx_http_next_request_body_filter(r, in);
}

// Post configuration - add request handler
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf) {
  // ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  // ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  // if (h == NULL) {
  //   return NGX_ERROR;
  // }
  // *h = ngx_http_jwt_request_handler;

  // Install jwt_issue_filter
  ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
  ngx_http_top_request_body_filter = ngx_http_jwt_issue_filter;

  return NGX_OK;
}
