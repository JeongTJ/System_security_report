#define PCRE2_CODE_UNIT_WIDTH 8
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <pcre2.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define LISTEN_PORT 8080
#define BACKEND_HOST "frontend"
#define BACKEND_PORT 3000
#define MAX_HEADER_SIZE 8192

#define NUM_RULES 5
static const char *PATTERNS[NUM_RULES] = {
    "<script",                                  // XSS tag
    "on[\\w]+\\s*=",
    "UNION.+SELECT",
    "SELECT.+FROM.+WHERE",
    "%3[cC](?:img|script)[^%]*onerror%3[dD]"
};
static pcre2_code *RULES[NUM_RULES];

typedef struct proxy_ctx_s {
    struct bufferevent *client_bev;
    struct bufferevent *backend_bev;
    struct evbuffer    *cached_req;
} proxy_ctx;

static int is_malicious(const char *data, size_t len) {
    for (int i = 0; i < NUM_RULES; i++) {
        pcre2_code *re = NULL;
        int rc = pcre2_compile(
            (PCRE2_SPTR)pattern_strings[i],
            PCRE2_ZERO_TERMINATED,
            PCRE2_CASELESS,
            &rc,
            NULL,
            NULL);
        if (rc >= 0) {
            int match_result = pcre2_match(re, (PCRE2_SPTR)data, len, 0, 0, NULL, NULL);
            pcre2_code_free(re);
            if (match_result >= 0) {
                return 1;
            }
        }
    }
    return 0;
}

static void close_ctx(proxy_ctx *ctx) {
    if(ctx->client_bev) bufferevent_free(ctx->client_bev);
    if(ctx->backend_bev) bufferevent_free(ctx->backend_bev);
    if(ctx->cached_req) evbuffer_free(ctx->cached_req);
    free(ctx);
}

static void relay_cb(struct bufferevent *src, void *arg) {
    proxy_ctx *ctx = (proxy_ctx*)arg;
    struct bufferevent *dst = (src == ctx->client_bev) ? ctx->backend_bev : ctx->client_bev;
    if(!dst) return;
    struct evbuffer *in = bufferevent_get_input(src);
    struct evbuffer *out = bufferevent_get_output(dst);
    evbuffer_add_buffer(out, in);
}

static void event_cb(struct bufferevent *bev, short events, void *arg) {
    proxy_ctx *ctx = (proxy_ctx*)arg;
    if(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        close_ctx(ctx);
    }
}

static void backend_connect_cb(struct bufferevent *bev, short events, void *arg) {
    proxy_ctx *ctx = (proxy_ctx*)arg;
    if(events & BEV_EVENT_CONNECTED) {
        if(ctx->cached_req) {
            bufferevent_write_buffer(ctx->backend_bev, ctx->cached_req);
            evbuffer_free(ctx->cached_req);
            ctx->cached_req = NULL;
        }
    } else if(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        close_ctx(ctx);
    }
}

static void client_read_cb(struct bufferevent *bev, void *arg) {
    proxy_ctx *ctx = (proxy_ctx*)arg;
    struct evbuffer *input = bufferevent_get_input(bev);

    size_t len = evbuffer_get_length(input);
    if(len == 0) return;
    unsigned char *data = evbuffer_pullup(input, len);

    if(strstr((char*)data, "\r\n\r\n") == NULL && len < MAX_HEADER_SIZE) {
        return; // wait more data
    }

    if(is_malicious((char*)data, len)) {
        const char *resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\nBlocked";
        bufferevent_write(bev, resp, strlen(resp));
        bufferevent_flush(bev, EV_WRITE, BEV_FLUSH);
        close_ctx(ctx);
        return;
    }

    struct event_base *base = bufferevent_get_base(bev);
    ctx->backend_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(ctx->backend_bev, relay_cb, NULL, backend_connect_cb, ctx);
    bufferevent_enable(ctx->backend_bev, EV_READ|EV_WRITE);

    ctx->cached_req = evbuffer_new();
    evbuffer_add_buffer(ctx->cached_req, input);

    bufferevent_socket_connect_hostname(ctx->backend_bev, NULL, AF_INET, BACKEND_HOST, BACKEND_PORT);

    bufferevent_setcb(bev, relay_cb, NULL, event_cb, ctx);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *arg) {
    struct event_base *base = (struct event_base*)arg;
    proxy_ctx *ctx = calloc(1, sizeof(proxy_ctx));

    ctx->client_bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(ctx->client_bev, client_read_cb, NULL, event_cb, ctx);
    bufferevent_enable(ctx->client_bev, EV_READ|EV_WRITE);
}

int main() {
    struct event_base *base = event_base_new();
    if(!base) { fprintf(stderr, "Could not init event base\n"); return 1; }

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0);
    sin.sin_port = htons(LISTEN_PORT);

    struct evconnlistener *listener = evconnlistener_new_bind(base, accept_conn_cb, base,
        LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr*)&sin, sizeof(sin));
    if(!listener) { perror("listener"); return 1; }

    printf("WAF listening on :%d, forwarding to %s:%d\n", LISTEN_PORT, BACKEND_HOST, BACKEND_PORT);

    for (int i=0; i<NUM_RULES; i++) {
        RULES[i] = pcre2_compile(
            (PCRE2_SPTR)PATTERNS[i],
            PCRE2_ZERO_TERMINATED,
            PCRE2_CASELESS,
            NULL,
            NULL,
            NULL);
    }

    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);

    for (int i=0; i<NUM_RULES; i++) {
        pcre2_code_free(RULES[i]);
    }

    return 0;
} 