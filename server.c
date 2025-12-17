#define STRINGBUF_IMPLEMENTATION
#include "stringbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "http.h"
#include "socket_server.h"

static void default_access_log(struct client_info *info, const char *action, size_t br, size_t bw) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S %z", tm);
    printf("%s - - [%s] \"%s\" 200 %zu %zu\n", info->addr, timebuf, action, br, bw);
}

static void default_error_log(const char *msg) {
    printf("ERROR: %s\n", msg);
}

struct path_entry {
    char *key;
    http_handler_t value;
};

struct base_entry {
    char *key;
    struct path_entry *value;
};

struct base_entry *base_handlers = NULL;

struct socket_handler_entry {
    char *key;
    socket_handler_t value;
};

struct socket_handler_entry *socket_handler_map = NULL;

static void default_http_handler(int fd, struct http_request *req, struct client_data *cd) {
    char body[512];
    snprintf(body, sizeof(body), "Welcome! Received request:\nMethod: %s\nURI: %s\nVersion: %s\nBody length: %zu\n",
             req->method ? req->method : "", req->uri ? req->uri : "", req->version ? req->version : "", req->body_len);
    struct http_response resp;
    memset(&resp, 0, sizeof(resp));
    resp.status_code = 200;
    resp.reason_phrase = "OK";
    struct http_header ct = {.key = "Content-Type", .value = "text/plain"};
    shputs(resp.headers, ct);
    resp.body = body;
    resp.body_len = strlen(body);
    char resp_buf[2048];
    size_t resp_len = http_build_response(&resp, resp_buf, sizeof(resp_buf));
    if (resp_len > 0) {
        socket_write(fd, resp_buf, resp_len);
    }
    shfree(resp.headers);
    char action[512];
    snprintf(action, sizeof(action), "%s %s %s", req->method ? req->method : "", req->uri ? req->uri : "", req->version ? req->version : "");
    default_access_log(&cd->info, action, 0, 0);
}

static void hello_http_handler(int fd, struct http_request *req, struct client_data *cd) {
    char body[512];
    snprintf(body, sizeof(body), "HELLO! Received request:\nMethod: %s\nURI: %s\nVersion: %s\nBody length: %zu\n",
             req->method ? req->method : "", req->uri ? req->uri : "", req->version ? req->version : "", req->body_len);
    struct http_response resp;
    memset(&resp, 0, sizeof(resp));
    resp.status_code = 200;
    resp.reason_phrase = "OK";
    struct http_header ct = {.key = "Content-Type", .value = "text/plain"};
    shputs(resp.headers, ct);
    resp.body = body;
    resp.body_len = strlen(body);
    char resp_buf[2048];
    size_t resp_len = http_build_response(&resp, resp_buf, sizeof(resp_buf));
    if (resp_len > 0) {
        socket_write(fd, resp_buf, resp_len);
    }
    shfree(resp.headers);
    char action[512];
    snprintf(action, sizeof(action), "%s %s %s", req->method ? req->method : "", req->uri ? req->uri : "", req->version ? req->version : "");
    default_access_log(&cd->info, action, 0, 0);
}

static void http_dispatcher(int fd, struct http_request *req, struct client_data *info) {
    ptrdiff_t base_idx = hmgeti(base_handlers, info->listen_uri);
    if (base_idx >= 0) {
        struct path_entry *paths = base_handlers[base_idx].value;
        ptrdiff_t path_idx = hmgeti(paths, req->uri);
        if (path_idx >= 0) {
            http_handler_t h = paths[path_idx].value;
            h(fd, req, info);
            return;
        }
    }
    default_http_handler(fd, req, info);
}

static void default_socket_handler(int fd, const char *data, size_t len, struct client_info *info) {
    if (info->type == CONN_UDPV4 || info->type == CONN_UDPV6) {
        socket_write(fd, data, len);
    } else {
        const char *msg = "Hello world!\n";
        socket_write(fd, msg, strlen(msg));
    }
}

void addHandler(const char *uri, void *handler_func) {
    const char *scheme_end = strstr(uri, "://");
    if (!scheme_end) return;
    char scheme[16];
    strncpy(scheme, uri, scheme_end - uri);
    scheme[scheme_end - uri] = '\0';

    const char *path_start = strchr(scheme_end + 3, '/');
    char *base_uri = strndup(uri, path_start ? path_start - uri : strlen(uri));
    char *path = path_start ? strdup(path_start) : strdup("/");

    bool is_http = (strcmp(scheme, "http") == 0 || strcmp(scheme, "https") == 0);

    if (is_http) {
        ptrdiff_t base_idx = hmgeti(base_handlers, base_uri);
        if (base_idx < 0) {
            struct path_entry *new_paths = NULL;
            hmput(base_handlers, base_uri, new_paths);
            base_idx = hmgeti(base_handlers, base_uri);
        }
        struct path_entry *paths = base_handlers[base_idx].value;
        hmput(paths, path, (http_handler_t)handler_func);
    } else {
        hmput(socket_handler_map, uri, (socket_handler_t)handler_func);
    }
    free(base_uri);
    free(path);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    char *cert_file = NULL;
    char *key_file = NULL;
    int i = 1;
    int default_backlog = 10;
    const char *uris[MAX_SOCKETS];
    int num_uris = 0;

    while (i < argc) {
        if (strcmp(argv[i], "-cert") == 0) {
            i++;
            if (i < argc) cert_file = argv[i];
            i++;
            continue;
        }
        if (strcmp(argv[i], "-key") == 0) {
            i++;
            if (i < argc) key_file = argv[i];
            i++;
            continue;
        }
        if (strcmp(argv[i], "-c") == 0) {
            i++;
            if (i < argc) {
                default_backlog = atoi(argv[i]);
            }
            i++;
            continue;
        }
        if (num_uris >= MAX_SOCKETS) {
            fprintf(stderr, "Too many URIs\n");
            return EXIT_FAILURE;
        }
        uris[num_uris++] = argv[i];
        i++;
    }

    if (cert_file && !key_file) {
        fprintf(stderr, "Error: -key required with -cert\n");
        return EXIT_FAILURE;
    }
    if (!cert_file && key_file) {
        fprintf(stderr, "Error: -cert required with -key\n");
        return EXIT_FAILURE;
    }

    struct server_sockets ss = {0};
    if (socket_server_add_sockets(&ss, uris, num_uris, default_backlog) < 0) {
        return EXIT_FAILURE;
    }

    for (int k = 0; k < ss.num_sockets; k++) {
        ptrdiff_t idx = hmgeti(socket_handler_map, ss.sockets[k].uri);
        if (idx >= 0) {
            ss.sockets[k].socket_handler = socket_handler_map[idx].value;
        }
    }

    bool needs_tls = false;
    for (int k = 0; k < ss.num_sockets; k++) {
        if (ss.sockets[k].is_tls) {
            needs_tls = true;
            break;
        }
    }
    if (needs_tls && !(cert_file && key_file)) {
        fprintf(stderr, "Error: -cert and -key required for ssl:// URIs\n");
        return EXIT_FAILURE;
    }

#ifdef HAVE_OPENSSL
    if (cert_file && key_file) {
        socket_server_init_tls(cert_file, key_file);
    }
#endif

    socket_server_init_hash();

    int loopfd = event_create();
    if (loopfd < 0) {
        log_sys_error(NULL, "event_create", errno);
        for (int k = 0; k < ss.num_sockets; k++) {
            for (int j = 0; j < ss.sockets[k].num_fds; j++) {
                close(ss.sockets[k].fds[j]);
            }
        }
        return EXIT_FAILURE;
    }

    if (socket_server_setup_loop(loopfd, &ss) < 0) {
        close(loopfd);
        for (int k = 0; k < ss.num_sockets; k++) {
            for (int j = 0; j < ss.sockets[k].num_fds; j++) {
                close(ss.sockets[k].fds[j]);
            }
        }
        return EXIT_FAILURE;
    }

    struct event_handlers handlers;
    socket_server_init_event_handlers(&handlers);
    handlers.on_access_log = default_access_log;
    handlers.on_error_log = default_error_log;
    handlers.on_http_request = http_dispatcher;

	addHandler("/hello", hello_http_handler);

    run_event_loop(loopfd, &ss, &handlers);

    hmfree(fd_to_index);
    return EXIT_SUCCESS;
}
