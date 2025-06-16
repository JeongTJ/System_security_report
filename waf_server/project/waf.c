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
#include <ctype.h>

#define LISTEN_PORT 8080
#define BACKEND_HOST "frontend"
#define BACKEND_PORT 3000
#define MAX_HEADER_SIZE 8192

#define NUM_RULES 5
static const char *PATTERNS[NUM_RULES] = {
    "<script",                                  // XSS tag
	"<img",
	"<script",
	"onerror=",
    "UNION.+SELECT",
    "SELECT.+FROM.+WHERE",
    "on[\\w]+\\s*=",
};
static pcre2_code *RULES[NUM_RULES];

typedef struct proxy_ctx_s {
    struct bufferevent *client_bev;
    struct bufferevent *backend_bev;
    struct evbuffer    *cached_req;
} proxy_ctx;

// 간단한 1회 퍼센트 디코딩 함수 (대소문자 허용)
static size_t url_decode(char *dst, const char *src, size_t len) {
    char *o = dst;
    for (size_t i = 0; i < len; i++) {
        if (src[i] == '%' && i + 2 < len && isxdigit((unsigned char)src[i + 1]) && isxdigit((unsigned char)src[i + 2])) {
            char hex[3] = { src[i + 1], src[i + 2], '\0' };
            *o++ = (char) strtol(hex, NULL, 16);
            i += 2;
        } else if (src[i] == '+') {
            *o++ = ' ';
        } else {
            *o++ = src[i];
        }
    }
    return o - dst;
}

static int is_malicious(const char *data, size_t len) {
    // 1) 원본 검사
	printf("=== data start ===\n");
	printf("%s", data);
	printf("\n=== data end   ===\n");
    for (int i = 0; i < NUM_RULES; i++) {
		printf("=== rules start ===\n");
		printf("%p", RULES[i]);
		printf("\n=== rules end   ===\n");
		size_t pattern_len = strlen(PATTERNS[i]);
		for (size_t data_idx = 0; data_idx < len - pattern_len; data_idx++) {
			size_t pattern_idx = 0;
			while (pattern_idx < pattern_len) {
				if (data[data_idx + pattern_idx] != PATTERNS[i][pattern_idx])
					break;
				pattern_idx++;
			}
			if (pattern_idx == pattern_len)
				return 1;
		}
        // if (!RULES[i]) continue;
        // if (pcre2_match(RULES[i], (PCRE2_SPTR)data, len, 0, 0, NULL, NULL) >= 0) {
        //     return 1;
        // }
    }

    // 2) URL 디코드 후 재검사 (퍼센트/플러스 처리)
    char decoded[MAX_HEADER_SIZE + 1];
    size_t dlen = url_decode(decoded, data, len);
    decoded[dlen] = '\0';
	printf("=== decoded start ===\n");
	printf("%s", decoded);
	printf("=== decoded end   ===\n");
    for (int i = 0; i < NUM_RULES; i++) {
		printf("=== rules start ===\n");
		printf("%p", RULES[i]);
		printf("\n=== rules end   ===\n");
		size_t pattern_len = strlen(PATTERNS[i]);
		for (size_t data_idx = 0; data_idx < len - pattern_len; data_idx++) {
			size_t pattern_idx = 0;
			while (pattern_idx < pattern_len) {
				if (decoded[data_idx + pattern_idx] != PATTERNS[i][pattern_idx])
					break;
				pattern_idx++;
			}
			if (pattern_idx == pattern_len)
				return 1;
		}
        // if (!RULES[i]) continue;
        // if (pcre2_match(RULES[i], (PCRE2_SPTR)decoded, dlen, 0, 0, NULL, NULL) >= 0) {
        //     return 1;
        // }
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

	int is_malicious_param = is_malicious((char*)data, len);

	printf("=== is_malicious_param start ===\n");
	printf("%d", is_malicious_param);
	printf("\n=== is_malicious_param end   ===\n");

    if(is_malicious_param) {
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

    for (int i = 0; i < NUM_RULES; i++) {
        int errcode; PCRE2_SIZE erroff;
        RULES[i] = pcre2_compile(
            (PCRE2_SPTR)PATTERNS[i],
            PCRE2_ZERO_TERMINATED,
            PCRE2_CASELESS,
            &errcode,
            &erroff,
            NULL);
        if (!RULES[i]) {
            fprintf(stderr, "[WAF] Regex compile failed for pattern %d (code %d) at offset %d\n",
                    i, errcode, (int)erroff);
        }
    }

    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);

    for (int i=0; i<NUM_RULES; i++) {
        pcre2_code_free(RULES[i]);
    }

    return 0;
} 