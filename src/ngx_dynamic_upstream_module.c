
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_dynamic_upstream_op.h"


typedef struct{
	ngx_str_t upstream_path;
}ngx_dynamic_upstream_conf_t;

ngx_str_t default_path = ngx_string("/home/work/nginx/conf/vhsot/");
static ngx_http_upstream_srv_conf_t *
ngx_dynamic_upstream_get_zone(ngx_http_request_t *r, ngx_dynamic_upstream_op_t *op);
static ngx_int_t
ngx_dynamic_upstream_create_response_buf(ngx_http_upstream_rr_peers_t *peers, ngx_buf_t *b, size_t size, ngx_int_t verbose);
static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r);
static char *
ngx_dynamic_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_dynamic_upstream_create_conf(ngx_conf_t *cf);
static char *ngx_dynamic_upstream_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);;
static char * ngx_dynamic_upstream_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_dump_upstream2file(ngx_http_request_t *r, ngx_str_t host, ngx_str_t zone_name, size_t zone_size, ngx_buf_t *buf);

static ngx_command_t ngx_dynamic_upstream_commands[] = {
    {
        ngx_string("dynamic_upstream"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_dynamic_upstream,
        0,
        0,
        NULL
    },
    {
        ngx_string("dynamic_upstream_path"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_dynamic_upstream_path,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_dynamic_upstream_conf_t,  upstream_path),
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t ngx_dynamic_upstream_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL, 
    NULL,                              /* create server configuration */

    ngx_dynamic_upstream_create_conf,                              /* create location configuration */
    ngx_dynamic_upstream_merge_conf                              /* merge location configuration */
};


ngx_module_t ngx_dynamic_upstream_module = {
    NGX_MODULE_V1,
    &ngx_dynamic_upstream_module_ctx, /* module context */
    ngx_dynamic_upstream_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_dynamic_upstream_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

        ngx_dynamic_upstream_conf_t* local_conf;

        local_conf = conf;
        char* rv = ngx_conf_set_str_slot(cf, cmd, conf);

        //ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "upstream_ptah:%s", local_conf->upstream_path.data);

	return rv;
}

static void *ngx_dynamic_upstream_create_conf(ngx_conf_t *cf)
{
        ngx_dynamic_upstream_conf_t  *conf = NULL;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_dynamic_upstream_conf_t));
        if (conf == NULL)
        {
                return NULL;
        }

	ngx_str_null(&conf->upstream_path);
        return conf;
}

static char *
ngx_dynamic_upstream_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_dynamic_upstream_conf_t *prev = parent;
    ngx_dynamic_upstream_conf_t *conf = child;


    ngx_conf_merge_str_value(conf->upstream_path, prev->upstream_path, default_path.data);
    return NGX_CONF_OK;
}

static void ngx_http_dump_upstream2file(ngx_http_request_t *r, ngx_str_t host, ngx_str_t zone_name, size_t zone_size, ngx_buf_t *buf){

    ngx_err_t                      err;
    ngx_file_t                     file;
    ngx_file_info_t                fi;
    ngx_buf_t                      *b;
    size_t                          len;

    ngx_dynamic_upstream_conf_t  *locf;
    locf = ngx_http_get_module_loc_conf(r, ngx_dynamic_upstream_module);
 
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "path, host  \"%s %s\" not found",
                           locf->upstream_path.data, host.data);
    ngx_memzero(&file, sizeof(ngx_file_t));
    len  = locf->upstream_path.len + host.len + 5;
    file.name.len = len;
    file.name.data = ngx_pnalloc(r->pool, len);
    ngx_sprintf(file.name.data, "%s%s.conf", locf->upstream_path.data, host.data);
    
    file.log = r->connection->log;
    // NGX_FILE_CREATE_OR_OPEN
    //file.fd = ngx_open_file(file.name.data, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);
    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDWR, NGX_FILE_TRUNCATE, 0);
    
    if (file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        /* cache file may have been deleted */

        if (err == NGX_ENOENT) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "upstream file  \"%s\" not found",
                           file.name.data);
        goto done;
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", file.name.data);
        goto done;
    }
    /*
     * make sure cache file wasn't replaced;
     * if it was, do nothing
     */

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", file.name.data);
        goto done;
    }

 
    //upstream xxx{ xxx }
    len = 8 + 1 + host.len*2 + 20  + (buf->last - buf->pos) + 4;
    b = ngx_create_temp_buf(r->pool, len);

    b->last = ngx_snprintf(b->last, len, "upstream %V{\nzone %V %dm;\n%s}\n", &host, &zone_name, zone_size, buf->pos);
    (void) ngx_write_file(&file, b->pos, (size_t)b->last - (size_t)b->pos, 0);

done:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file.name.data);
    }
}



static ngx_http_upstream_srv_conf_t *
ngx_dynamic_upstream_get_zone(ngx_http_request_t *r, ngx_dynamic_upstream_op_t *op)
{
    ngx_uint_t                      i;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf  = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        if (uscf->shm_zone != NULL &&
            uscf->shm_zone->shm.name.len == op->upstream.len &&
            ngx_strncmp(uscf->shm_zone->shm.name.data, op->upstream.data, op->upstream.len) == 0)
        {
            return uscf;
        }
    }

    return NULL;
}    


static ngx_int_t
ngx_dynamic_upstream_create_response_buf(ngx_http_upstream_rr_peers_t *peers, ngx_buf_t *b, size_t size, ngx_int_t verbose)
{
    ngx_http_upstream_rr_peer_t  *peer;
    u_char                        namebuf[512], *last;

    last = b->last + size;

    for (peer = peers->peer; peer; peer = peer->next) {

        if (peer->name.len > 511) {
            return NGX_ERROR;
        }

        ngx_cpystrn(namebuf, peer->name.data, peer->name.len + 1);

        if (verbose) {
            b->last = ngx_snprintf(b->last, last - b->last, "server %s weight=%d max_fails=%d fail_timeout=%d",
                                   namebuf, peer->weight, peer->max_fails, peer->fail_timeout, peer->down);

        } else {
            b->last = ngx_snprintf(b->last, last - b->last, "server %s", namebuf);

        }

        b->last = peer->down ? ngx_snprintf(b->last, last - b->last, " down;\n") : ngx_snprintf(b->last, last - b->last, ";\n");
    }

    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r)
{
    size_t                          size;
    ngx_int_t                       rc;
    ngx_chain_t                     out;
    ngx_dynamic_upstream_op_t       op;
    ngx_buf_t                      *b;
    ngx_http_upstream_srv_conf_t   *uscf;
    ngx_slab_pool_t                *shpool;
    
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }
    
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    rc = ngx_dynamic_upstream_build_op(r, &op);
    if (rc != NGX_OK) {
        if (op.status == NGX_HTTP_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return op.status;
    }
    
    uscf = ngx_dynamic_upstream_get_zone(r, &op);
    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream is not found. %s:%d",
                      __FUNCTION__,
                      __LINE__);
        return NGX_HTTP_NOT_FOUND;
    }

    shpool = (ngx_slab_pool_t *) uscf->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    
    rc = ngx_dynamic_upstream_op(r, &op, shpool, uscf);
    if (rc != NGX_OK) {
        ngx_shmtx_unlock(&shpool->mutex);
        if (op.status == NGX_HTTP_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return op.status;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    size = uscf->shm_zone->shm.size;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    rc = ngx_dynamic_upstream_create_response_buf((ngx_http_upstream_rr_peers_t *)uscf->peer.data, b, size, 1);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to create a response. %s:%d",
                      __FUNCTION__,
                      __LINE__);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }



    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    ngx_http_dump_upstream2file(r, uscf->host, uscf->shm_zone->shm.name, size/1024/1024, b);
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_dynamic_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_dynamic_upstream_handler;

    return NGX_CONF_OK;
}
