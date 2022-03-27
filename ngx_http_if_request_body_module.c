
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define MODULE_NAME "nginx_if_request_body"

typedef struct {
    ngx_http_complex_value_t rule;
    ngx_int_t status;
    ngx_flag_t is_starts_with;
    ngx_flag_t case_sensitive;
} body_eq_rule;

typedef struct {
    ngx_http_complex_value_t rule;
} variable_map_rule;

typedef struct {
    ngx_http_complex_value_t rule;
    ngx_int_t status;
    ngx_flag_t case_sensitive;
} body_contains_rule;

typedef struct {
    ngx_regex_t *rule;
    ngx_int_t status;
} body_regex_rule;


// Header out
typedef struct {
    ngx_str_t key;
    ngx_http_complex_value_t   value;
} body_with_header_t;


typedef struct {
    ngx_flag_t         enable;
    ngx_flag_t         include_body;
    ngx_array_t        *headers_for_body_matched;
    ngx_array_t        *return_if_variable_map_to;
    ngx_array_t        *return_if_body_eq_rules;
    ngx_array_t        *return_if_body_contains_rules;
    ngx_array_t        *return_if_body_regex_rules;
} ngx_http_if_request_body_conf_t;

typedef struct {
    ngx_int_t     forward_status;
    ngx_flag_t    include_body;
} ngx_http_if_request_body_ctx_t;



static void *ngx_http_if_request_body_create_conf(ngx_conf_t *cf);
static char *ngx_http_if_request_body_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_if_request_body_init(ngx_conf_t *cf);

static char *ngx_http_add_header_if_body_matched(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_if_variable_map_to(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_if_request_body_set_if_regex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_if_request_body_set_if_eq(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_if_request_body_set_if_startswith(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_if_request_body_set_if_contains(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_if_request_body_handler(ngx_http_request_t *r);



static u_char *ngx_http_if_request_body_strncasestr(u_char *s1, size_t len1, u_char *s2, size_t len2);
static u_char *ngx_http_if_request_body_strnstr(u_char *s1, size_t len1, u_char *s2, size_t len2);
static ngx_int_t ngx_http_if_request_body_massage_header(ngx_http_request_t *r, ngx_http_if_request_body_conf_t *bcf);
static ngx_int_t ngx_http_if_request_body_add_header_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *val );


static ngx_command_t  ngx_http_if_request_body_commands[] = {

    { ngx_string("if_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
// ngx_http_if_request_body_set_flag_slot
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_if_request_body_conf_t, enable),
      NULL },
    { ngx_string("return_with_body"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
// ngx_http_if_request_body_set_flag_slot
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_if_request_body_conf_t, include_body),
      NULL },
    { ngx_string("add_header_if_body_matched"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE2,
      ngx_http_add_header_if_body_matched,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("return_status_if_variable_map_to"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_if_variable_map_to,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("return_status_if_body_eq"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_if_request_body_set_if_eq,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("return_status_if_body_startswith"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_if_request_body_set_if_startswith,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("return_status_if_body_contains"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_if_request_body_set_if_contains,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("return_status_if_body_regex"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_if_request_body_set_if_regex,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_if_request_body_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_if_request_body_init,      /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_if_request_body_create_conf, /* create location configuration */
    ngx_http_if_request_body_merge_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_if_request_body_module = {
    NGX_MODULE_V1,
    &ngx_http_if_request_body_module_ctx, /* module context */
    ngx_http_if_request_body_commands,  /* module directives */
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


// static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;

// Return the Final Status
static ngx_int_t
ngx_http_if_request_body_filter(ngx_http_request_t *r) {
    u_char                      *p;
    ngx_str_t                   req_body;
    ngx_chain_t                 *cl;
    ngx_http_if_request_body_conf_t  *bcf;
    ngx_buf_t                   *b;
    size_t                      len;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "intercept request body and filtered");
    
    bcf = ngx_http_get_module_loc_conf(r, ngx_http_if_request_body_module);
    

    // TO GET THE LEN FIRST
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        goto SKIP_CHECKING;
    }

    if (r->request_body->bufs->next != NULL) {
        len = 0;
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            b = cl->buf;
            if (b->in_file) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "insufficient client_body_buffer_size, expand it before checking");
                goto SKIP_CHECKING;
            }
            len += b->last - b->pos;
        }
        if (len == 0) {
            goto SKIP_CHECKING;
        }


        p = req_body.data = ngx_palloc(r->pool, len);
        req_body.len = len;

        if (p == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "insufficient memory.");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }
    } else {
        b = r->request_body->bufs->buf;
        if ( !b->pos || (len = ngx_buf_size(b)) == 0) {
            goto SKIP_CHECKING;
        }
        req_body.data = b->pos;
        req_body.len = len;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "checking body : | %V |", &req_body);

    // CHECK THE RULE NOW

    ngx_uint_t i, nelts;
    body_eq_rule *eq_rules;
    body_contains_rule *contains_rules;
    body_regex_rule *regex_rules;
    variable_map_rule *map_rules;
    ngx_str_t check_value;

    // EQ OR STARTSWITH RULE
    if( bcf->return_if_body_eq_rules != NULL ){
        eq_rules =  bcf->return_if_body_eq_rules->elts;
        nelts = bcf->return_if_body_eq_rules->nelts;

        for (i = 0; i < nelts; i++) {
            if (ngx_http_complex_value(r, &eq_rules->rule, &check_value) == NGX_OK) {
                if(eq_rules->is_starts_with) {
                    if(req_body.len >= check_value.len){
                        if(eq_rules->case_sensitive) {
                            if(ngx_strncmp(req_body.data, check_value.data, check_value.len) == 0) {
                                if(ngx_http_if_request_body_massage_header(r, bcf) != NGX_OK) {
                                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                                }
                                return eq_rules->status;
                            }
                        } else if (ngx_strncasecmp(req_body.data, check_value.data, check_value.len) == 0) {
                                if(ngx_http_if_request_body_massage_header(r, bcf) != NGX_OK) {
                                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                                }
                                return eq_rules->status;
                        }
                    }
                } else if(req_body.len == check_value.len) {
                    if(eq_rules->case_sensitive) {
                        if(ngx_strncmp(check_value.data, req_body.data, req_body.len) == 0) {
                            if(ngx_http_if_request_body_massage_header(r, bcf) != NGX_OK) {
                                return NGX_HTTP_INTERNAL_SERVER_ERROR;
                            }
                            return eq_rules->status;
                        }
                    } else if (ngx_strncasecmp(check_value.data, req_body.data, req_body.len) == 0) {
                            if(ngx_http_if_request_body_massage_header(r, bcf) != NGX_OK) {
                                return NGX_HTTP_INTERNAL_SERVER_ERROR;
                            }
                            return eq_rules->status;
                    }
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "error when checking the request body");
            }
            eq_rules++;
        }
    }
    // EQ OR STARTSWITH RULE END

    // CONTAINS RULE
    if( bcf->return_if_body_contains_rules != NULL ){

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "checking contains rule");
        contains_rules =  bcf->return_if_body_contains_rules->elts;
        nelts = bcf->return_if_body_contains_rules->nelts;

        for (i = 0; i < nelts; i++) {
            if (ngx_http_complex_value(r, &contains_rules->rule, &check_value) == NGX_OK) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "checking request body \"%V\", with rule \"%V\"",
                                            &req_body, &check_value);
                if(req_body.len >= check_value.len) {
                    if(contains_rules->case_sensitive) {
                        if( (ngx_http_if_request_body_strnstr(req_body.data, req_body.len,check_value.data,check_value.len)) ) {
                            if(ngx_http_if_request_body_massage_header(r, bcf) != NGX_OK) {
                                return NGX_HTTP_INTERNAL_SERVER_ERROR;
                            }
                            return contains_rules->status;
                        }
                    } else if ( (ngx_http_if_request_body_strncasestr(req_body.data, req_body.len,check_value.data,check_value.len)) ) {
                        if(ngx_http_if_request_body_massage_header(r, bcf) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                        return contains_rules->status;
                    }
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "error when checking the request body");
            }
            contains_rules++;
        }
    }
    // CONTAINS RULE END


    // REGEX RULE

    if( bcf->return_if_body_regex_rules != NULL ){
        regex_rules =  bcf->return_if_body_regex_rules->elts;
        nelts = bcf->return_if_body_regex_rules->nelts;

        for (i = 0; i < nelts; i++) {
        
            ngx_int_t  n;
            int        captures[3];


            n = ngx_regex_exec(regex_rules->rule, &req_body, captures, 3);
            if (n >= 0) {
                if(ngx_http_if_request_body_massage_header(r, bcf) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                /* string matches expression */
                return regex_rules->status;

            } else if (n == NGX_REGEX_NO_MATCHED) {
                /* no match was found */
            } else {
                /* some error */
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, ngx_regex_exec_n " failed: %i", n);
            }


            regex_rules++;
        }
    }
    // REGEX RULE END

// Proceed to the next handler of the current phase. 
// If the current handler is the last in the current phase, move to the next phase.
SKIP_CHECKING:
    // VARIABLE MAP RULE EXTRA BONUS CHECK REGARDLESS have body or not
    if( bcf->return_if_variable_map_to != NULL ){
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Checking map rule process");

        map_rules =  bcf->return_if_variable_map_to->elts;
        nelts = bcf->return_if_variable_map_to->nelts;

        for (i = 0; i < nelts; i++) {
            if (ngx_http_complex_value(r, &map_rules->rule, &check_value) == NGX_OK) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "the value is %V", &check_value);

                if(check_value.len > 0) {
                    ngx_int_t status = ngx_atoi(check_value.data, check_value.len);
                    if (status == NGX_ERROR) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }
                    if(status != 100) { // if 100 Means bypass
                        if(ngx_http_if_request_body_massage_header(r, bcf) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                        return status;
                    }
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "error when checking the map rules");
            }
            map_rules++;
        }
    }
    // VARIABLE MAP RULE END
    return NGX_DECLINED;
}


static void *
ngx_http_if_request_body_create_conf(ngx_conf_t *cf)
{
    ngx_http_if_request_body_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_if_request_body_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->include_body = NGX_CONF_UNSET;
    conf->headers_for_body_matched = NGX_CONF_UNSET_PTR;
    conf->return_if_variable_map_to = NGX_CONF_UNSET_PTR;
    conf->return_if_body_eq_rules = NGX_CONF_UNSET_PTR;
    conf->return_if_body_contains_rules = NGX_CONF_UNSET_PTR;
    conf->return_if_body_regex_rules = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_if_request_body_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_if_request_body_conf_t *prev = parent;
    ngx_http_if_request_body_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->include_body, prev->include_body, 1);

    ngx_conf_merge_ptr_value(conf->headers_for_body_matched, prev->headers_for_body_matched, NULL);
    ngx_conf_merge_ptr_value(conf->return_if_variable_map_to, prev->return_if_variable_map_to, NULL);
    ngx_conf_merge_ptr_value(conf->return_if_body_eq_rules, prev->return_if_body_eq_rules, NULL);
    ngx_conf_merge_ptr_value(conf->return_if_body_contains_rules, prev->return_if_body_contains_rules, NULL);
    ngx_conf_merge_ptr_value(conf->return_if_body_regex_rules, prev->return_if_body_regex_rules, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_if_request_body_init(ngx_conf_t *cf)
{

    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    // ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    // ngx_http_top_request_body_filter = ngx_http_if_request_body_filter;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_if_request_body_handler;

    return NGX_OK;

    return NGX_OK;
}

static char *
ngx_http_if_request_body_set_if_eq_(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, ngx_flag_t is_starts_with) {
    ngx_http_if_request_body_conf_t   *bcf = conf;
    ngx_str_t                         *value;
    body_eq_rule                      *br;   
    // The complex value is to resolve variable feature
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;
    

    if (bcf->return_if_body_eq_rules == NULL || bcf->return_if_body_eq_rules == NGX_CONF_UNSET_PTR) {
        bcf->return_if_body_eq_rules = ngx_array_create(cf->pool, 2,
                                                sizeof(body_eq_rule));
        if (bcf->return_if_body_eq_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    br = ngx_array_push(bcf->return_if_body_eq_rules);
    if (br == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &br->rule;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // TAKE 2
    br->status = ngx_atoi(value[2].data, value[2].len);
    if (br->status == NGX_ERROR) {
        return "invalid status code";
    }



    if(cf->args->nelts == 4){
        if (ngx_strcasecmp(value[3].data, (u_char *) "on") == 0) {
            br->case_sensitive = 1;
        } else if (ngx_strcasecmp(value[3].data, (u_char *) "off") == 0) {
            br->case_sensitive = 0;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid value \"%s\" in \"%s\" directive, "
                        "it must be \"on\" or \"off\"",
                        value[3].data, cmd->name.data);
            return NGX_CONF_ERROR;
        }
    } else {
        br->case_sensitive = 1;
    }


    br->is_starts_with = is_starts_with;

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                        "rule eq \"%V\", with status \"%d\" has been register",
                        &br->rule, br->status);

    return NGX_CONF_OK;
}

static char *
ngx_http_if_request_body_set_if_eq(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    return ngx_http_if_request_body_set_if_eq_(cf, cmd, conf, 0);
}


static char *
ngx_http_if_request_body_set_if_startswith(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    return ngx_http_if_request_body_set_if_eq_(cf, cmd, conf, 1);
}

static char *
ngx_http_if_request_body_set_if_contains(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_if_request_body_conf_t        *bcf = conf;
    ngx_str_t                         *value;
    body_contains_rule                      *br;   
    // The complex value is to resolve variable feature
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;
    

    if (bcf->return_if_body_contains_rules == NULL || bcf->return_if_body_contains_rules == NGX_CONF_UNSET_PTR) {
        bcf->return_if_body_contains_rules = ngx_array_create(cf->pool, 2,
                                                sizeof(body_contains_rule));
        if (bcf->return_if_body_contains_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    br = ngx_array_push(bcf->return_if_body_contains_rules);
    if (br == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &br->rule;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // TAKE 2
    br->status = ngx_atoi(value[2].data, value[2].len);
    if (br->status == NGX_ERROR) {
        return "invalid status code";
    }



    if(cf->args->nelts == 4){
        if (ngx_strcasecmp(value[3].data, (u_char *) "on") == 0) {
            br->case_sensitive = 1;
        } else if (ngx_strcasecmp(value[3].data, (u_char *) "off") == 0) {
            br->case_sensitive = 0;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid value \"%s\" in \"%s\" directive, "
                        "it must be \"on\" or \"off\"",
                        value[3].data, cmd->name.data);
            return NGX_CONF_ERROR;
        }
    } else {
        br->case_sensitive = 1;
    }


    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                        "rule eq \"%V\", with status \"%d\" has been register",
                        &br->rule, br->status);

    return NGX_CONF_OK;
}



static char *
ngx_http_if_request_body_set_if_regex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_if_request_body_conf_t  *bcf = conf;

    ngx_str_t                   *value;
    body_regex_rule             *br;   
    ngx_regex_compile_t          rc;
    u_char                       errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;
    value++;

    if (bcf->return_if_body_regex_rules == NULL || bcf->return_if_body_regex_rules == NGX_CONF_UNSET_PTR) {
        bcf->return_if_body_regex_rules = ngx_array_create(cf->pool, 2,
                                                sizeof(body_regex_rule));
        if (bcf->return_if_body_regex_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    br = ngx_array_push(bcf->return_if_body_regex_rules);
    if (br == NULL) {
        return NGX_CONF_ERROR;
    }


    memset (&rc,'\0',sizeof(ngx_regex_compile_t));

    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pattern = *value;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_CONF_ERROR;
    }

    br->rule = rc.regex;

    // TAKE 2
    value++;
    br->status = ngx_atoi(value->data, value->len);
    if (br->status == NGX_ERROR) {
        return "invalid status code";
    }


    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                        "rule regex \"%s\", with status \"%d\" has been register",
                        &rc.pattern, br->status);

    return  NGX_CONF_OK;
}


static void
ngx_http_if_request_body_process(ngx_http_request_t *r) {
    ngx_http_if_request_body_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_if_request_body_module);

    ctx->forward_status = ngx_http_if_request_body_filter(r);

    // In order to pass body as well when returning status
    r->preserve_body = ctx->include_body;

    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}

/**
* This is Precontent Handler 
*/
static ngx_int_t
ngx_http_if_request_body_handler(ngx_http_request_t *r){
    ngx_int_t                            rc;
    ngx_http_if_request_body_ctx_t       *ctx;
    ngx_http_if_request_body_conf_t      *bcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    bcf = ngx_http_get_module_loc_conf(r, ngx_http_if_request_body_module);

    if (!bcf->enable) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "if request body handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_if_request_body_module);

    if (ctx) {
        return ctx->forward_status;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_if_request_body_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->forward_status = NGX_DONE;
    ctx->include_body = bcf->include_body;

    ngx_http_set_ctx(r, ctx, ngx_http_if_request_body_module);

    rc = ngx_http_read_client_request_body(r, ngx_http_if_request_body_process);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    ngx_http_finalize_request(r, NGX_DONE);

    return NGX_DONE;
}


static char *
ngx_http_if_variable_map_to(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_if_request_body_conf_t   *bcf = conf;
    ngx_str_t                         *value;
    variable_map_rule                      *br;   
    // The complex value is to resolve variable feature
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (bcf->return_if_variable_map_to == NULL || bcf->return_if_variable_map_to == NGX_CONF_UNSET_PTR) {
        bcf->return_if_variable_map_to = ngx_array_create(cf->pool, 2,
                                                sizeof(variable_map_rule));
        if (bcf->return_if_variable_map_to == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    br = ngx_array_push(bcf->return_if_variable_map_to);
    if (br == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &br->rule;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return  NGX_CONF_OK;
}


static char *
ngx_http_add_header_if_body_matched(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_if_request_body_conf_t         *bcf = conf;
    ngx_str_t                               *value;
    body_with_header_t                      *hdr;
    ngx_http_compile_complex_value_t        ccv;

    value = cf->args->elts;

    if (bcf->headers_for_body_matched == NULL || bcf->headers_for_body_matched == NGX_CONF_UNSET_PTR) {
        bcf->headers_for_body_matched = ngx_array_create(cf->pool, 2,
                                                sizeof(body_with_header_t));
        if (bcf->headers_for_body_matched == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    hdr = ngx_array_push(bcf->headers_for_body_matched);
    if (hdr == NULL) {
        return NGX_CONF_ERROR;
    }

    hdr->key = value[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &hdr->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_http_if_request_body_massage_header(ngx_http_request_t *r, ngx_http_if_request_body_conf_t *bcf) {
    ngx_uint_t i, nelts;
    body_with_header_t *hdrs;
    ngx_str_t hdr_val;
    ngx_array_t *headers_for_body_matched;

    if(bcf->headers_for_body_matched) {
        headers_for_body_matched = bcf->headers_for_body_matched;
        hdrs = headers_for_body_matched->elts;
        nelts = headers_for_body_matched->nelts;

        for (i = 0; i < nelts; i++) {
            if (ngx_http_complex_value(r, &hdrs->value, &hdr_val) == NGX_OK) {
                if (ngx_http_if_request_body_add_header_out(r, &hdrs->key, &hdr_val) == NGX_ERROR) {
                    return NGX_ERROR;
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                    "unable to parse headers %V ", &hdrs->key);
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}



static ngx_int_t
ngx_http_if_request_body_add_header_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *val ) {
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "insufficient memory.");
        return NGX_ERROR;
    }
    h->hash = 1; /*to mark HTTP output headers show set 1, show missing set 0*/
    h->key.len = key->len;
    h->key.data = key->data;
    h->value.len = val->len;
    h->value.data = val->data;
    return NGX_OK;
}


// REFER ngx_string.c in order to compare case sensitive and second string len
u_char *
ngx_http_if_request_body_strnstr(u_char *s1, size_t len1, u_char *s2, size_t len2)
{
    u_char  c1, c2;

    c2 = *(u_char *) s2++;
    len2--;

    do {
        do {
            if (len1-- == 0) {
                return NULL;
            }

            c1 = *s1++;

            if (c1 == 0) {
                return NULL;
            }

        } while (c1 != c2);

        if (len2 > len1) {
            return NULL;
        }

    } while (ngx_strncmp(s1, (u_char *) s2, len2) != 0);

    return --s1;
}

u_char *
ngx_http_if_request_body_strncasestr(u_char *s1, size_t len1, u_char *s2, size_t len2)
{
    u_char  c1, c2;

    c2 = *(u_char *) s2++;
    len2--;

    do {
        do {
            if (len1-- == 0) {
                return NULL;
            }

            c1 = *s1++;

            if (c1 == 0) {
                return NULL;
            }

        } while (c1 != c2);

        if (len2 > len1) {
            return NULL;
        }

    } while (ngx_strncasecmp(s1, (u_char *) s2, len2) != 0);

    return --s1;
}