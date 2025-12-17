#ifndef REQUEST_H
#define REQUEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <stdbool.h>

#include "http.h"
#include "socket_server.h"
#ifndef INCLUDE_STB_DS_H
#  include "stb_ds.h" 
#endif

struct path_entry {
    char *key;
    http_handler_t value;
};

struct base_entry {
    char *key;
    struct path_entry *value;
};

struct socket_handler_entry {
    char *key;
    socket_handler_t value;
};

extern struct base_entry *base_handlers;
extern struct path_entry *global_http_handlers;
extern struct socket_handler_entry *socket_handler_map;

static inline void default_access_log(struct client_info *info, const char *action, size_t br, size_t bw) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S %z", tm);
    printf("%s - - [%s] \"%s\" 200 %zu %zu\n", info->addr, timebuf, action, br, bw);
}

static inline void default_error_log(const char *msg) {
    printf("ERROR: %s\n", msg);
}

static inline void http_ok(int fd, const char *content, ssize_t content_length, const char *content_type) {
    struct http_response resp = {
        .status_code = 200,
        .reason_phrase = "OK",
        .body = NULL,
        .body_len = content_length
    };
    struct http_header ct = {.key = "Content-Type", .value = (char *)content_type};
    shputs(resp.headers, ct);
    struct http_header server = {.key = "Server", .value = "NanoServer/0.1"};
    shputs(resp.headers, server);

    char resp_buf[2048];
    size_t resp_len = http_build_response(&resp, resp_buf, sizeof(resp_buf));
    if (resp_len > 0) {
        socket_write(fd, resp_buf, resp_len);
        if (content_length > 0 && content) {
            socket_write(fd, content, content_length);
        }
    }
    shfree(resp.headers);
}

static inline void default_http_handler(int fd, struct http_request *req, struct client_data *cd) {
    char body[512];
    ssize_t body_len = snprintf(body, sizeof(body), "Welcome! Received request:\nMethod: %s\nURI: %s\nVersion: %s\nBody length: %zu\n",
                                req->method ? req->method : "", req->uri ? req->uri : "", req->version ? req->version : "", req->body_len);
    http_ok(fd, body, body_len, "text/plain");
}

static inline void hello_http_handler(int fd, struct http_request *req, struct client_data *cd) {
    char body[512];
    ssize_t body_len = snprintf(body, sizeof(body), "HELLO! Received request:\nMethod: %s\nURI: %s\nVersion: %s\nBody length: %zu\n",
                                req->method ? req->method : "", req->uri ? req->uri : "", req->version ? req->version : "", req->body_len);
    http_ok(fd, body, body_len, "text/plain");
}

static inline void http_dispatcher(int fd, struct http_request *req, struct client_data *info) {
    char action[512];
    snprintf(action, sizeof(action), "%s %s %s", req->method ? req->method : "", req->uri ? req->uri : "", req->version ? req->version : "");

    ptrdiff_t base_idx = shgeti(base_handlers, info->listen_uri);
    if (base_idx >= 0) {
        struct path_entry *paths = base_handlers[base_idx].value;
        ptrdiff_t path_idx = shgeti(paths, req->uri);
        if (path_idx >= 0) {
            http_handler_t h = paths[path_idx].value;
            h(fd, req, info);
            default_access_log(&info->info, action, 0, 0);
            return;
        }
    }
    ptrdiff_t global_idx = shgeti(global_http_handlers, req->uri);
    if (global_idx >= 0) {
        http_handler_t h = global_http_handlers[global_idx].value;
        h(fd, req, info);
        default_access_log(&info->info, action, 0, 0);
        return;
    }
    default_http_handler(fd, req, info);
    default_access_log(&info->info, action, 0, 0);
}

static inline void default_socket_handler(int fd, const char *data, size_t len, struct client_info *info) {
    if (info->type == CONN_UDPV4 || info->type == CONN_UDPV6) {
        socket_write(fd, data, len);
    } else {
        const char *msg = "Hello world!\n";
        socket_write(fd, msg, strlen(msg));
    }
}

static inline void addHandler(const char *uri, void *handler_func) {
    size_t uri_len = strlen(uri);
    if (uri_len > MAX_URL_SIZE) return;

    if (uri[0] == '/') {
        char *key = strndup(uri, MAX_URL_SIZE);
        if (!key) return;
        struct path_entry pe = {.key = key, .value = (http_handler_t)handler_func};
        shputs(global_http_handlers, pe);
        return;
    }

    const char *scheme_end = strstr(uri, "://");
    if (!scheme_end) return;
    size_t scheme_len = scheme_end - uri;
    if (scheme_len == 0 || scheme_len >= 16) return;
    char scheme[16];
    strncpy(scheme, uri, scheme_len);
    scheme[scheme_len] = '\0';

    const char *path_start = strchr(scheme_end + 3, '/');
    size_t base_len = path_start ? path_start - uri : uri_len;
    if (base_len > MAX_URL_SIZE) return;
    char *base_uri = strndup(uri, base_len);
    if (!base_uri) return;

    char *path;
    if (path_start) {
        size_t path_len = uri_len - (path_start - uri);
        if (path_len > MAX_URL_SIZE) {
            free(base_uri);
            return;
        }
        path = strndup(path_start, path_len);
    } else {
        path = strdup("/");
    }
    if (!path) {
        free(base_uri);
        return;
    }

    bool is_http = (strcmp(scheme, "http") == 0 || strcmp(scheme, "https") == 0);

    if (is_http) {
        ptrdiff_t base_idx = shgeti(base_handlers, base_uri);
        if (base_idx < 0) {
            struct path_entry *new_paths = NULL;
            struct base_entry be = {.key = base_uri, .value = new_paths};
            shputs(base_handlers, be);
            base_idx = shgeti(base_handlers, base_uri);
        }
        struct path_entry *paths = base_handlers[base_idx].value;
        struct path_entry pe = {.key = path, .value = (http_handler_t)handler_func};
        shputs(paths, pe);
    } else {
        char *key = strndup(uri, MAX_URL_SIZE);
        if (!key) {
            free(base_uri);
            free(path);
            return;
        }
        struct socket_handler_entry she = {.key = key, .value = (socket_handler_t)handler_func};
        shputs(socket_handler_map, she);
        free(base_uri);
        free(path);
    }
}

#endif /* REQUEST_H */
