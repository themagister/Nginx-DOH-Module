
/*
 * Copyright (C) Colin Taylor
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t       doh_enabled;
    ngx_str_t        doh_addr;
    ngx_uint_t       doh_port;
    ngx_msec_t       doh_timeout;
    socklen_t        doh_socklen;
    struct sockaddr* doh_sockinfo;
} ngx_http_doh_loc_conf_t;

typedef struct {
    ngx_buf_t*          q;
    ngx_http_request_t* r;
    uint16_t            id;
} ngx_http_doh_request_t;

static void* ngx_http_doh_create_loc_conf(ngx_conf_t* cf);
static char* ngx_http_doh_merge_loc_conf(ngx_conf_t* cf, void* prev,
    void* conf);
static char* ngx_http_doh(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
static ngx_int_t ngx_http_doh_send_query(ngx_http_doh_request_t* req);
static ngx_int_t ngx_http_doh_send_tcp_query(ngx_http_doh_request_t* req);
static ngx_int_t ngx_http_doh_handler(ngx_http_request_t* r);
static void ngx_http_doh_read_handler(ngx_event_t* rev);
static void ngx_http_doh_tcp_read_handler(ngx_event_t* rev);
static void ngx_http_doh_tcp_write_handler(ngx_event_t* wev);
static void ngx_http_doh_post_handler(ngx_http_request_t* r);
static ngx_int_t ngx_http_doh_minttl(ngx_buf_t* buf, uint32_t* minTTL);

#define NGX_DEF_DNS_ADDR "127.0.0.1"
#define NGX_DEF_DNS_PORT 53
#define NGX_DEF_DNS_TOUT 5000
#define NGX_DNS_MAX_SIZE 4096 /*see section 6.2.5 of RFC 6891*/
#define NGX_DNS_MIN_SIZE 21 /*size of DNS header + query type/class in
                              base64url*/
#define NGX_DNS_TC       0x0200
#define NGX_TCP_SIZE     65536
#define NGX_TTL_SIZE     18 /*max-age= + digits of a 32-bit unsigned integer*/


static ngx_command_t ngx_http_doh_commands[] = {
    { ngx_string("doh"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_doh,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("doh_address"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, doh_addr),
      NULL },

    { ngx_string("doh_port"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, doh_port),
      NULL },

    { ngx_string("doh_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, doh_timeout),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_doh_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_doh_create_loc_conf,
    ngx_http_doh_merge_loc_conf
};

ngx_module_t ngx_http_doh_module = {
    NGX_MODULE_V1,
    &ngx_http_doh_module_ctx,
    ngx_http_doh_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_doh_handler(ngx_http_request_t* r)
{
    ngx_buf_t*              b;
    ngx_http_doh_request_t* req;
    ngx_int_t               rc;
    ngx_str_t               coded, query;
    size_t                  len;
    uint16_t                id;

    if (r->headers_in.content_type == NULL || !r->headers_in.content_type->hash
        || ngx_strcmp(r->headers_in.content_type->value.data,
                      "application/dns-message") != 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

#if (NGX_HTTP_HEADERS)
    if (r->headers_in.accept == NULL || !r->headers_in.accept->hash) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "accept not set");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_strcmp(r->headers_in.accept->value.data, "application/dns-message")
        != 0 && ngx_strcmp(r->headers_in.accept->value.data, "*/*") != 0) {
        return NGX_HTTP_BAD_REQUEST;
    }
#endif

    ngx_str_set(&r->headers_out.content_type, "application/dns-message");
    if (r->method == NGX_HTTP_GET)
    {
        if (r->args.len <= NGX_DNS_MIN_SIZE
            || ngx_strncmp((const char *)r->args.data, "dns=", 4) != 0) {
            return NGX_HTTP_BAD_REQUEST;
        }

        req = ngx_pcalloc(r->pool, sizeof(ngx_http_doh_request_t));
        if (req == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        req->r = r;
        r->count++;

        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        b->start = ngx_pcalloc(r->pool, NGX_DNS_MAX_SIZE);
        if(b->start == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        b->end = b->start + NGX_DNS_MAX_SIZE;
        b->pos = b->start;
        b->last = b->pos;

        ngx_memzero(&query, sizeof(ngx_str_t));
        ngx_memcpy(&coded, &r->args, sizeof(ngx_str_t));

        /*skip over the dns= part*/
        coded.data+=4;
        coded.len-=4;

        len = ngx_base64_decoded_length(coded.len);
        query.data = b->pos;
        query.len = len;

        rc = ngx_decode_base64url(&query, &coded);
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(b->pos, query.data, len);
        b->last = b->pos + len;
        b->memory = 1;

        /*according to RFC 8484 DOH clients SHOULD set the ID field of queries
         to 0, however this may cause problems with upstream resolvers, so add
         one here*/
        id = htons(rand() % 65536);
        ngx_memcpy(&req->id, b->pos, sizeof(uint16_t));
        ngx_memcpy(b->pos, &id, sizeof(uint16_t));
        req->q = b;

        rc = ngx_http_doh_send_query(req);
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "couldn't send query");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        else {
            return NGX_DONE;
        }
    }

    else if (r->method == NGX_HTTP_POST) {
        rc = ngx_http_read_client_request_body(r, ngx_http_doh_post_handler );
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        else {
            return NGX_DONE;
        }
    } 

    else {
        return NGX_HTTP_NOT_ALLOWED;
    }
}


static void
ngx_http_doh_post_handler(ngx_http_request_t* r)
{
    ngx_buf_t*              b;
    ngx_chain_t*            in;
    ngx_http_doh_request_t* req;
    ngx_int_t               rc;
    size_t                  size;
    uint16_t                id;

    if (r->request_body == NULL) {
        goto failed;
    }

    req = ngx_pcalloc(r->pool, sizeof(ngx_http_doh_request_t));
    if (req == NULL) {
        goto failed;
    }
    req->r = r;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        goto failed;
    }
    b->start = ngx_pcalloc(r->pool, NGX_DNS_MAX_SIZE);
    if (b->start == NULL) {
        goto failed;
    }
    b->end = b->start + NGX_DNS_MAX_SIZE;
    b->pos = b->start;
    b->last = b->pos;

    for (in = r->request_body->bufs; in; in = in->next) {
        size = ngx_buf_size(in->buf);
        if (size > 0 && size < (size_t)(b->end - b->last)) {
            ngx_memcpy(b->last, in->buf->pos, size);
            b->last+=size;
        }

        else {
            goto failed;
        }
    }
    b->memory = 1;

    /*according to RFC 8484 DOH clients SHOULD set the ID field of queries
     to 0, however this may cause problems with upstream resolvers, so add
     one here*/
    id = htons(rand() % 65536);
    ngx_memcpy(&req->id, b->pos, sizeof(uint16_t));
    ngx_memcpy(b->pos, &id, sizeof(uint16_t));
    req->q = b;

    rc = ngx_http_doh_send_query(req);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "couldn't send query");
        goto failed;
    }

    return;

failed:

    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
}


static ngx_int_t
ngx_http_doh_send_query(ngx_http_doh_request_t* req)
{
    ngx_buf_t*               b;
    ngx_connection_t*        con;
    ngx_event_t              *rev, *wev;
    ngx_http_doh_loc_conf_t* dlcf;
    ngx_http_request_t*      r;
    ngx_int_t                event, rc;
    ngx_socket_t             sock;
    ssize_t                  n, size;

    if (req == NULL) {
        return NGX_ERROR;
    }

    r = req->r;
    b = req->q;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);
    if (dlcf == NULL) {
        return NGX_ERROR;
    }

    sock = ngx_socket(dlcf->doh_sockinfo->sa_family, SOCK_DGRAM, 0);
    if (sock == -1) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    con = ngx_get_connection(sock, r->connection->log);
    if (con == NULL) {
        if (ngx_close_socket(sock) == -1) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }

    if (ngx_nonblocking(sock) == -1) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");
        goto failed;
    }

    con->data = req;
    con->log = r->connection->log;
    con->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    con->pool = r->pool;

    con->socklen = dlcf->doh_socklen;
    con->sockaddr = ngx_pcalloc(r->pool, con->socklen);
    if (con->sockaddr == NULL) {
        goto failed;
    }

    ngx_memcpy(con->sockaddr, dlcf->doh_sockinfo, con->socklen);
    rev = con->read;
    rev->handler = ngx_http_doh_read_handler;
    rev->log = con->log;

    rc = connect(sock, dlcf->doh_sockinfo, dlcf->doh_socklen);
    if (rc == -1) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                      "UDP connect() failed");
        goto failed;
    }

    wev = con->write;
    wev->log = con->log;
    wev->ready = 1;

    size = b->last - b->pos;
    n = ngx_udp_send(con, b->pos, size);
    if (n != size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "send() failed");
        goto failed;
    }
 
    event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ? NGX_CLEAR_EVENT:
                                                      NGX_LEVEL_EVENT;
    rc = ngx_add_event(rev, NGX_READ_EVENT, event);
    if (rc != NGX_OK) {
        goto failed;
    }
    
    ngx_add_timer(rev, dlcf->doh_timeout);

    return NGX_OK;

failed:

    ngx_close_connection(con);
    return NGX_ERROR;
}


static void
ngx_http_doh_read_handler(ngx_event_t* rev)
{
    ngx_buf_t*          b;
    ngx_chain_t         out;
    ngx_connection_t*   con;
    ngx_http_request_t* r;
    ngx_int_t           rc;
    ngx_table_elt_t     *cc, **ccp;
    ssize_t              n;
    u_char              cache[NGX_TTL_SIZE];
    uint32_t            min_ttl; 

    con = rev->data;
    r = ((ngx_http_doh_request_t*)con->data)->r;

    if (rev->timedout) {
        r->headers_out.status = NGX_HTTP_NO_CONTENT;
        goto failed;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
    }

    b->start = ngx_pcalloc(r->pool, NGX_DNS_MAX_SIZE);
    if(b->start == NULL) {
        r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
    }
    b->end = b->start + NGX_DNS_MAX_SIZE;
    b->pos = b->start;
    b->last = b->pos;

    n = ngx_udp_recv(con, b->pos, NGX_DNS_MAX_SIZE);
    if (n < 0) {
        r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
    }

    if (n == 0) {
        r->headers_out.status = NGX_HTTP_NO_CONTENT;
        r->headers_out.content_length_n = 0;
        goto failed;
    }

    if (*(uint16_t *)(b->pos + 2) & NGX_DNS_TC) {
        if (ngx_http_doh_send_tcp_query(con->data) != NGX_OK) {
            r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto failed;
        }

        ngx_close_connection(con);
        return;
    }

    /*restore original ID*/
    ngx_memcpy(b->pos, &((ngx_http_doh_request_t*)con->data)->id,
               sizeof(uint16_t));

    b->last = b->pos + n;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    ngx_array_init(&r->headers_out.cache_control, r->pool,
                   1, sizeof(ngx_table_elt_t *));
    cc = ngx_list_push(&r->headers_out.headers);
    cc->hash = 1;
    ngx_str_set(&cc->key, "Cache-Control");
    rc = ngx_http_doh_minttl(b, &min_ttl);
    if (rc == NGX_ERROR) {
        ngx_str_set(&cc->value, "no-store");
    }

    else {
        ngx_memzero(cache, NGX_TTL_SIZE * sizeof(u_char));
        ngx_snprintf(cache, NGX_TTL_SIZE, "max-age=%D", min_ttl);
        cc->value.data = cache;
        cc->value.len = ngx_strlen(cache);
    }
    ccp = ngx_array_push(&r->headers_out.cache_control);
    *ccp = cc;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = n;

    rc = ngx_http_send_header(r);
    if (!(rc == NGX_ERROR || rc > NGX_OK || r->header_only)) {
         rc = ngx_http_output_filter(r, &out);
    }

    ngx_http_finalize_request(r, rc);
    ngx_handle_read_event(rev, 0);
    ngx_close_connection(con);
    return;

failed:

    rc = ngx_http_send_header(r);
    ngx_http_finalize_request(r, rc);
    ngx_close_connection(con);
    return;
}


static ngx_int_t
ngx_http_doh_send_tcp_query(ngx_http_doh_request_t* req)
{
    ngx_buf_t                *b, *query;
    ngx_connection_t*        con;
    ngx_event_t              *rev, *wev;
    ngx_http_doh_loc_conf_t* dlcf;
    ngx_http_request_t*      r;
    ngx_int_t                event, rc;
    ngx_socket_t             sock;
    uint16_t                 len;

    if (req == NULL) {
        return NGX_ERROR;
    }

    r = req->r;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);
    if (dlcf == NULL) {
        return NGX_ERROR;
    }

    b = req->q;
    len = (uint16_t)(b->last - b->pos);
    query = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (query == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(query, sizeof(ngx_buf_t));
    query->start = ngx_pcalloc(r->pool, len + 2);
    if (query->start == NULL) {
        return NGX_ERROR;
    }

    query->pos = query->start + 2;
    query->end = query->pos + len;
    query->last = query->end;

    ngx_memcpy(query->pos, b->start, len);
    len = htons(len);
    ngx_memcpy(query->start, &len, sizeof(uint16_t));

    query->pos = query->start;
    req->q = query;

    sock = ngx_socket(dlcf->doh_sockinfo->sa_family, SOCK_STREAM, 0);
    if (sock == -1) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    con = ngx_get_connection(sock, r->connection->log);
    if (con == NULL) {
        if (ngx_close_socket(sock) == -1) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }
        return NGX_ERROR;
    }
    con->data = req;
    con->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    con->pool = r->pool;

    if (ngx_nonblocking(sock) == -1) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");
        goto failed;
    }

    rev = con->read;
    rev->handler = ngx_http_doh_tcp_read_handler;
    rev->log = r->connection->log;

    wev = con->write;
    wev->handler = ngx_http_doh_tcp_write_handler;
    wev->log = r->connection->log;

    rc = connect(sock, dlcf->doh_sockinfo, dlcf->doh_socklen);
    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS
#if (NGX_WIN32)
        && ngx_errno != NGX_EAGAIN
#endif
        )
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                      "TCP connect() failed");
        goto failed;
    }

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        if (ngx_blocking(sock) == -1) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                          ngx_blocking_n " failed");
            goto failed;
        }

        rev->ready = 1;
        wev->ready = 1;
        return NGX_OK;
    }

    event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ? NGX_CLEAR_EVENT:
                                                      NGX_LEVEL_EVENT;

    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
        goto failed;
    }

    if (rc == -1) {
        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            goto failed;
        }

        ngx_add_timer(wev, dlcf->doh_timeout);
    }

    else {
        wev->ready = 1;
    }

    return NGX_OK;

failed:

    ngx_close_connection(con);
    return NGX_ERROR;
}


static void
ngx_http_doh_tcp_read_handler(ngx_event_t* rev)
{
    ngx_buf_t           *b;
    ngx_chain_t         out;
    ngx_connection_t*   con;
    ngx_http_request_t* r;
    ngx_int_t           rc;
    ngx_table_elt_t     *cc, **ccp;
    ssize_t             n;
    u_char              cache[NGX_TTL_SIZE], response[NGX_TCP_SIZE];
    uint32_t            min_ttl;

    con = rev->data;
    r = ((ngx_http_doh_request_t*)con->data)->r;

    if (rev->timedout) {
        r->headers_out.status = NGX_HTTP_NO_CONTENT;
        r->headers_out.content_length_n = 0;
        goto failed;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
    }

    n = 0;
    while (rev->ready) {
        n = ngx_recv(con, response + n, NGX_TCP_SIZE);
        if (n < 0) {
            ngx_log_error(NGX_LOG_ALERT, con->log, 0, "TCP recv() error");
            r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto failed;
        }

        if (n == 0) {
            r->headers_out.status = NGX_HTTP_NO_CONTENT;
            r->headers_out.content_length_n = 0;
            goto failed;
        }
    }

    b->start = ngx_pcalloc(r->pool, NGX_TCP_SIZE);
    if (b->start == NULL) {
        r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
    }

    b->pos = b->start;
    b->end = b->start + NGX_TCP_SIZE;

    /*do not include TCP length in output*/
    n-=2;
    ngx_memcpy(b->pos, response + 2, n);
    b->last = b->pos + n;

    /*restore original ID*/
    ngx_memcpy(b->pos, &((ngx_http_doh_request_t*)con->data)->id,
               sizeof(uint16_t));

    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    ngx_array_init(&r->headers_out.cache_control, r->pool,
                   1, sizeof(ngx_table_elt_t *));
    cc = ngx_list_push(&r->headers_out.headers);
    cc->hash = 1;
    ngx_str_set(&cc->key, "Cache-Control");
    rc = ngx_http_doh_minttl(b, &min_ttl);
    if (rc == NGX_ERROR) {
        ngx_str_set(&cc->value, "no-store");
    }

    else {
        ngx_memzero(cache, NGX_TTL_SIZE * sizeof(u_char));
        ngx_snprintf(cache, NGX_TTL_SIZE, "max-age=%D", min_ttl);
        cc->value.data = cache;
        cc->value.len = ngx_strlen(cache);
    }
    ccp = ngx_array_push(&r->headers_out.cache_control);
    *ccp = cc;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = n;

    rc = ngx_http_send_header(r);
    if (!(rc == NGX_ERROR || rc > NGX_OK || r->header_only)) {
        rc = ngx_http_output_filter(r, &out);
    }

    ngx_http_finalize_request(r, rc);
    ngx_handle_read_event(rev, 0);
    ngx_close_connection(con);
    return;

failed:

    rc = ngx_http_send_header(r);
    ngx_http_finalize_request(r, rc);
    ngx_close_connection(con);
}


static void ngx_http_doh_tcp_write_handler(ngx_event_t* wev)
{
    ngx_buf_t*          b;
    ngx_connection_t*   con;
    ngx_http_request_t* r;
    ngx_int_t           rc;
    ssize_t             n;

    con = wev->data;
    b = ((ngx_http_doh_request_t*)con->data)->q;

    if (wev->timedout) {
        goto failed;
    }

    while (wev->ready && b->pos < b->last) {
        n = ngx_send(con, b->pos, b->last - b->pos);
        if (n > 0) {
            b->pos+=n;
        }

        if (n < 0) {
            ngx_log_error(NGX_LOG_ALERT, con->log, 0, "TCP failed to send");
            goto failed;
        }
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK)
        goto failed;
    else
        return;

failed:

    r = ((ngx_http_doh_request_t*)con->data)->r;
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    rc = ngx_http_send_header(r);
    ngx_http_finalize_request(r, rc);
    ngx_close_connection(con);
    return;
}


static ngx_int_t 
ngx_http_doh_minttl(ngx_buf_t* buf, uint32_t* minTTL)
{
    size_t    offset;
    u_char*   byte_data;
    uint16_t  num_questions, *short_data;
    uint32_t* long_data, num_records, temp;

    if (buf == NULL || minTTL == NULL) {
        return NGX_ERROR;
    }

    /*make sure the response was not an error*/
    if (ntohs(*(uint16_t *)(buf->pos + 2)) & 0x000f) {
        return NGX_ERROR;
    }

    /*get the number of questions*/
    num_questions = ntohs(*(uint16_t *)(buf->pos + 4));

    /*find the number of records in the response*/
    num_records = ntohs(*(uint16_t *)(buf->pos + 6));
    num_records+=ntohs(*(uint16_t *)(buf->pos + 8));
    num_records+=ntohs(*(uint16_t *)(buf->pos + 10));

    /*get to the end of the question section*/
    offset = 12;
    do {
        byte_data = buf->pos + offset;
        if ((*byte_data & 0xc0) == 0xc0) {
            offset+=6;
        }

        else {
            while (*byte_data != 0) {
                offset++;
                byte_data = buf->pos + offset;
            }
            offset+=5;
        }
        num_questions--;
    } while (num_questions > 0);

    /*get the minimum TTL*/
    *minTTL = 0xffffffff;
    do {
        byte_data = buf->pos + offset;
        if ((*byte_data & 0xc0) == 0xc0) {
            long_data = (uint32_t *)(buf->pos + offset + 6);
            short_data = (uint16_t *)(buf->pos + offset + 10);
            offset+=(12 + ntohs(*short_data));
        }

        else {
            while (*byte_data != 0) {
                offset++;
                byte_data = buf->pos + offset;
            }
            long_data = (uint32_t *)(buf->pos + offset + 5);
            short_data = (uint16_t *)(buf->pos + offset + 9);
            offset+=(11 + ntohs(*short_data));
        }
        temp = ntohl(*long_data);
        if (temp < *minTTL) {
            *minTTL = temp;
        }
        num_records--;
    } while (num_records > 0);

    return NGX_OK;
}


static char*
ngx_http_doh(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    ngx_http_core_loc_conf_t* clcf;
    ngx_http_doh_loc_conf_t*  dlcf;
    
    dlcf = conf;
    dlcf->doh_enabled = 1;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_doh_handler;

    return NGX_CONF_OK;
}


static void*
ngx_http_doh_create_loc_conf(ngx_conf_t* cf)
{
    ngx_http_doh_loc_conf_t* conf;
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_doh_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->doh_addr.data = NULL;
    conf->doh_addr.len = 0;
    conf->doh_port = NGX_CONF_UNSET_UINT;
    conf->doh_timeout = NGX_CONF_UNSET_MSEC;
    
    return conf;
}


static char*
ngx_http_doh_merge_loc_conf(ngx_conf_t* cf, void* prev, void* conf)
{
    ngx_http_doh_loc_conf_t* config;
    ngx_http_doh_loc_conf_t* pconfig;
    ngx_uint_t               ipv4addr;
    struct sockaddr_in*      tempv4;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6*     tempv6;
    u_char                   ipv6addr[16];
#endif

    config = conf;
    pconfig = prev;
    ngx_conf_merge_str_value(config->doh_addr, pconfig->doh_addr,
                             NGX_DEF_DNS_ADDR);
    ngx_conf_merge_uint_value(config->doh_port, pconfig->doh_port,
                              NGX_DEF_DNS_PORT);
    ngx_conf_merge_msec_value(config->doh_timeout, pconfig->doh_timeout,
                              NGX_DEF_DNS_TOUT);

    ipv4addr = ngx_inet_addr(config->doh_addr.data, config->doh_addr.len);
    if (ipv4addr == INADDR_NONE) {
#if (NGX_HAVE_INET6)
        if (ngx_inet6_addr(config->doh_addr.data, config->doh_addr.len,
                          ipv6addr) == NGX_OK) {
            tempv6 = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in6));
            if (tempv6 == NULL) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "memory error");
                return NGX_CONF_ERROR;
            }

            ngx_memzero(tempv6, sizeof(struct sockaddr_in6));
            tempv6->sin6_family = AF_INET6;
            tempv6->sin6_port = htons(config->doh_port);
            ngx_memcpy(tempv6->sin6_addr.s6_addr, ipv6addr, 16);
            config->doh_sockinfo = (struct sockaddr *)tempv6;
            config->doh_socklen = sizeof(struct sockaddr_in6);

            return NGX_CONF_OK;
        }

        else {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "doh_address: invalid ip address");
            return NGX_CONF_ERROR;
        }
#endif
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "doh_address: invalid ip address");
        return NGX_CONF_ERROR;
    }

    tempv4 = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in));
    if (tempv4 == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "memory error");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(tempv4, sizeof(struct sockaddr_in));
    tempv4->sin_family = AF_INET;
    tempv4->sin_port = htons(config->doh_port);
    tempv4->sin_addr.s_addr = ipv4addr;
    config->doh_sockinfo = (struct sockaddr *)tempv4;
    config->doh_socklen = sizeof(struct sockaddr_in);

    return NGX_CONF_OK;
}
