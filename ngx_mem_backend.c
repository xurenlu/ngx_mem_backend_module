/*
 * Copyright (C) Evan Miller
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#define radius2index(r, cglcf) (r-(cglcf)->min_radius)/(cglcf)->step_radius
#define DD printf("run into here:%s,%d\n",__FILE__,__LINE__);
//#define DD 
// these are effectively two-dimensional arrays

//static void* ngx_http_mem_backend_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_mem_backend_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char * ngx_http_cf_mem_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_http_mem_backend_create_loc_conf(ngx_conf_t *cf);

typedef struct {
    ngx_http_upstream_conf_t upstream;
    ngx_str_t mem_backend;
    ngx_flag_t           enable;
} ngx_http_mem_backend_loc_conf_t;

static ngx_int_t ngx_http_mem_backend_init(ngx_http_mem_backend_loc_conf_t *cf);

static ngx_command_t  ngx_http_mem_backend_commands[] = {
    { ngx_string("mem_backend"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_cf_mem_backend,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mem_backend_loc_conf_t, mem_backend),
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_mem_backend_ctx = {
    NULL,                          /* preconfiguration */
    NULL,           /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    ngx_http_mem_backend_create_loc_conf,  /* create location configuration */
    ngx_http_mem_backend_merge_loc_conf /* merge location configuration */
};


ngx_module_t  ngx_mem_backend= {
    NGX_MODULE_V1,
    &ngx_http_mem_backend_ctx, /* module context */
    ngx_http_mem_backend_commands,   /* module directives */
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

static ngx_int_t
ngx_http_mem_backend_create_request(ngx_http_request_t *r)
{
/* make a buffer and chain */
    printf("ngx_http_mem_backend_create_request called\n");
    ngx_buf_t *b,*b2,*b3;
    ngx_chain_t *cl,*cl2,*cl3;


    b2 = ngx_create_temp_buf(r->pool,4);
    if (b2 == NULL)
         return NGX_ERROR;
    DD
    cl2 = ngx_alloc_chain_link(r->pool);
    if (cl2 == NULL)
         return NGX_ERROR;
/* hook the buffer to the chain */
    DD
    cl2->buf = b2;
    b2->pos=(u_char *)("get ");
    b2->last=b2->pos+4; 
    r->upstream->request_bufs = cl2;
    
    DD
    b = ngx_create_temp_buf(r->pool,r->uri.len);
    if (b == NULL)
         return NGX_ERROR;
    DD
    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL)
         return NGX_ERROR;
/* hook the buffer to the chain */
    DD
    cl->buf = b;
    cl2->next=cl;
/* chain to the upstream */
    b->pos=(u_char *)(r->uri.data);
    b->last=b->pos+r->uri.len;

    b3=ngx_create_temp_buf(r->pool,2);
    if(b3==NULL)
        return NGX_ERROR;
    cl3=ngx_alloc_chain_link(r->pool);
    if(cl3==NULL)
        return NGX_ERROR;
    cl->next=cl3;
    cl3->next=NULL;
    cl3->buf=b3;
    b3->pos=(u_char *)("\n\r");
    b3->last=b3->pos+2;
    b3->last_buf=1;
    DD
/* now write to the buffer */
    //b->pos = "a";
    //b->last = b->pos + sizeof("a") - 1;
    return NGX_OK;
}
static ngx_int_t
ngx_http_mem_backend_reinit_request(ngx_http_request_t *r){
    printf("ngx_http_mem_backend_reinit_request called\n");
    return NGX_OK;
}
static ngx_int_t 
ngx_http_mem_backend_process_status_line(ngx_http_request_t *r){
    printf("ngx_http_mem_backend_process_status_line called\n\n\n\n");
    ngx_int_t rc;
    ngx_chain_t   out;
    DD
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    DD
    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }
    DD
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    DD
    printf("hello world\n");
    //printf("echo:%s\n",cglcf->echo.data);
    ngx_buf_t    *b;
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    DD
    b->pos=r->upstream->buffer.pos;
    b->last=r->upstream->buffer.last-3;
    b->last_buf=1;
    b->memory=1;
    out.buf = b;
    out.next = NULL;
    DD
    return ngx_http_output_filter(r, &out);
}
static void  
ngx_http_mem_backend_abort_request(ngx_http_request_t *r){
    printf("ngx_http_mem_backend_abort_request called\n");
    return ;
}
static void  
ngx_http_mem_backend_finalize_request(ngx_http_request_t *r,ngx_int_t rc){
    printf("ngx_http_mem_backend_finalize_request called\n");
    return ;
}

static ngx_int_t
ngx_http_mem_backend_handler(ngx_http_request_t *r)
{
    printf("ngx_http_mem_backend_handler called\n");
     ngx_int_t                   rc;
     ngx_http_upstream_t        *u;
     ngx_http_mem_backend_loc_conf_t *plcf;
     plcf = ngx_http_get_module_loc_conf(r, ngx_mem_backend);
/* set up our upstream struct */
     u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
     if (u == NULL) {
         return NGX_HTTP_INTERNAL_SERVER_ERROR;
     }
     DD
    u->schema.len=sizeof("mem://")-1;
     u->schema.data=(u_char *)"mem://";

     //u->peer.log = r->connection->log;
     //u->peer.log_error = NGX_ERROR_ERR;
     u->output.tag = (ngx_buf_tag_t) &ngx_mem_backend;
     u->conf = &plcf->upstream;
/* attach the callback functions */
     u->create_request = ngx_http_mem_backend_create_request;
     u->reinit_request = ngx_http_mem_backend_reinit_request;
     u->process_header = ngx_http_mem_backend_process_status_line;
     u->abort_request = ngx_http_mem_backend_abort_request;
     u->finalize_request = ngx_http_mem_backend_finalize_request;
     
     u->buffering=1;
     u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
     if (u->pipe == NULL) {
         return NGX_HTTP_INTERNAL_SERVER_ERROR;
     }
        u->pipe->input_ctx=r;

     DD
     r->upstream = u;
     rc = ngx_http_read_client_request_body(r,ngx_http_upstream_init);
     DD
     printf("rc:%d\n",rc);
     DD
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
         DD
         return rc;
    }
    else{
        DD
        return NGX_DONE;
    }
}

static char *
ngx_http_cf_mem_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    printf("ngx_http_cf_mem_backend called,we got new configuration:\n");
    ngx_url_t                   u;
    ngx_str_t                  *value, *url;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_mem_backend_loc_conf_t *cglcf = conf;
    ngx_uint_t n;
    if (cglcf->upstream.upstream) {
        return "is duplicate";
    }
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mem_backend_handler;
    value = cf->args->elts;
    url = &value[1];
    printf("the mem_backend string:%s\n",(*url).data);
    n = ngx_http_script_variables_count(url);
    /**
    if(!n){
        printf("the error:script_variables_count error!\n");
        return "erorr:need arguments for mem_backend";
    }
    */
    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.no_resolve = 1;
    cglcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (cglcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }
    cglcf->enable = 1;
    cglcf->mem_backend=*(ngx_str_t *)cf->args->elts;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_mem_backend_init(ngx_http_mem_backend_loc_conf_t *cglcf)
{
    printf("ngx_http_mem_backend_init called\n");
  u_int i;
  i=5;
  return i;
}


static void *
ngx_http_mem_backend_create_loc_conf(ngx_conf_t *cf)
{
    printf("ngx_http_mem_backend_create_loc_conf called\n");
    ngx_http_mem_backend_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mem_backend_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->mem_backend.len=0;
    conf->mem_backend.data=NULL;
    conf->enable = NGX_CONF_UNSET;


    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

#if (NGX_HTTP_CACHE)
    conf->upstream.cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
#endif

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

    /* "fastcgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;


    return conf;
}

static char *
ngx_http_mem_backend_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    printf("ngx_http_mem_backend_merge_loc_conf called\n");

    size_t size;
    ngx_http_mem_backend_loc_conf_t *prev = parent;
    ngx_http_mem_backend_loc_conf_t *conf = child;

    //ngx_conf_merge_str_value(conf->mem_backend, prev->mem_backend, ngx_string("localhost:11211"));
    ngx_conf_merge_value(conf->enable, prev->enable, 0);



    if (conf->upstream.store != 0) {
        ngx_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        if (conf->upstream.store_lengths == NULL) {
            conf->upstream.store_lengths = prev->upstream.store_lengths;
            conf->upstream.store_values = prev->upstream.store_values;
        }
    }

    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    ngx_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);


    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"fastcgi_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be equal or bigger than "
             "maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be less than "
             "the size of all \"fastcgi_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_temp_file_write_size\" must be equal or bigger than "
             "maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_max_temp_file_size\" must be equal to zero to disable "
             "the temporary files usage or must be equal or bigger than "
             "maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              NGX_CONF_BITMASK_SET);


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    /**
    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &ngx_http_fastcgi_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    */

#if (NGX_HTTP_CACHE)

    ngx_conf_merge_ptr_value(conf->upstream.cache,
                              prev->upstream.cache, NULL);

    if (conf->upstream.cache && conf->upstream.cache->data == NULL) {
        ngx_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"fastcgi_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
                                         |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

#endif

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);




    if(conf->enable)
        ngx_http_mem_backend_init(conf);
    return NGX_CONF_OK;
}
