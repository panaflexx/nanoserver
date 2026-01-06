#ifndef REQUEST_H
#define REQUEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "http.h"
#include "socket_server.h"
#ifndef INCLUDE_STB_DS_H
#  include "stb_ds.h"
#endif

//#define CHUNK_SIZE 4096

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

struct Location {
    char *real_path;
    uid_t user;
    gid_t group;
};

typedef struct {
    char *key;
    struct Location value;
} LocationEntry;

extern struct base_entry *base_handlers;
extern struct path_entry *global_http_handlers;
extern struct socket_handler_entry *socket_handler_map;
extern LocationEntry *locations;
extern struct event_handlers handlers;

static inline void resume_send(int loopfd, int fd);

static inline void addLocation(const char *prefix, const char *real_path, uid_t user, gid_t group) {
    char *p = strdup(prefix);
    if (!p) return;
    char *rp = strdup(real_path);
    if (!rp) {
        free(p);
        return;
    }
    struct Location loc = {.real_path = rp, .user = user, .group = group};
    hmputs(locations, ((LocationEntry){.key = p, .value = loc}) );
}

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


static inline void http_add_connection_header(struct http_response *resp, bool keep_alive) {
    struct http_header conn = {
        .key = "Connection",
        .value = keep_alive ? "keep-alive" : "close"
    };
    // Avoid duplicates
    ptrdiff_t idx = shgeti(resp->headers, "Connection");
    if (idx >= 0) {
        free(resp->headers[idx].value);
        resp->headers[idx].value = strdup(conn.value);
    } else {
        shputs(resp->headers, conn);
    }
}

static inline struct http_response_log http_ok(http_p *p, const char *content, ssize_t content_length,
												const char *content_type) 
{
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
	http_add_connection_header(&resp, true);

    char resp_buf[2048];
    size_t resp_len = http_build_response(&resp, resp_buf, sizeof(resp_buf));
    if (resp_len > 0) {
        socket_write(p->fd, resp_buf, resp_len);
        if (content_length > 0 && content) {
            socket_write(p->fd, content, content_length);
        }
    }
    shfree(resp.headers);
	return ((struct http_response_log){ .status_code = 200, .br=0, .bw=resp_len});
}

static inline struct http_response_log http_error(http_p *p, int status_code, const char *reason_phrase) {
    struct http_response resp = {
        .status_code = status_code,
        .reason_phrase = (char *)reason_phrase,
        .body = NULL,
        .body_len = 0
    };
    struct http_header server = {.key = "Server", .value = "NanoServer/0.1"};
    shputs(resp.headers, server);

    char resp_buf[2048];
    size_t resp_len = http_build_response(&resp, resp_buf, sizeof(resp_buf));
    if (resp_len > 0) {
        socket_write(p->fd, resp_buf, resp_len);
    }
    shfree(resp.headers);
	
	fprintf(stderr, "http_error: %d - %d [%s]\n", p->fd, status_code, reason_phrase);

	return ((struct http_response_log){ .status_code = status_code, .br=0, .bw=resp_len});
}

static inline void default_http_handler(http_p *p, struct http_request *req, struct client_data *cd) {
    char body[512];
    ssize_t body_len = snprintf(body, sizeof(body),
							"Welcome! Received request:\nMethod: %s\nURI: %s\nVersion: %s\nBody length: %zu\n",
                            req->method ? req->method : "", req->uri ? req->uri : "",
							req->version ? req->version : "", req->body_len);
    http_ok(p, body, body_len, "text/plain");
}

static inline void hello_http_handler(http_p *p, struct http_request *req, struct client_data *cd) {
    char body[512];
    ssize_t body_len = snprintf(body, sizeof(body),
							"HELLO! Received request:\nMethod: %s\nURI: %s\nVersion: %s\nBody length: %zu\n",
                            req->method ? req->method : "", req->uri ? req->uri : "",
							req->version ? req->version : "", req->body_len);
    http_ok(p, body, body_len, "text/plain");
}

static inline const char *get_mime_type(const char *path) {
    static struct { const char *ext; const char *type; } mimes[] = {
        {".html", "text/html"},
        {".htm", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".json", "application/json"},
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".gif", "image/gif"},
        {".svg", "image/svg+xml"},
        {".txt", "text/plain"},
        {".mp4", "video/mp4"},
        {NULL, NULL}
    };

    size_t path_len = strlen(path);
    for (int i = 0; mimes[i].ext; ++i) {
        size_t ext_len = strlen(mimes[i].ext);
        if (path_len >= ext_len && strcasecmp(path + path_len - ext_len, mimes[i].ext) == 0) {
            return mimes[i].type;
        }
    }
    return "application/octet-stream";
}

static inline void directory_handler(http_p *p, struct http_request *req, struct client_data *cd) {
    if (strcmp(req->method, "GET") != 0) {
        http_error(p, 405, "Method Not Allowed");
        return;
    }
    const char *prefix = cd->matched_prefix;
    if (!prefix) {
        http_error(p, 500, "Internal Server Error");
        return;
    }
    ptrdiff_t loc_idx = hmgeti(locations, (char*)prefix);
    const char *root;
    if (loc_idx >= 0) {
        root = locations[loc_idx].value.real_path;
    } else {
        root = "./public";
    }
    const char *subpath = req->uri + strlen(prefix);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", root, subpath);
    if (strlen(path) >= PATH_MAX - 1) {
        http_error(p, 414, "URI Too Long");
        return;
    }
    char real_path[PATH_MAX];
    if (realpath(path, real_path) == NULL) {
        http_error(p, 403, "Forbidden");
        fprintf(stderr, "realpath failed: %s\n", path);
        return;
    }
	// FIXME: This doesn't work because we need to compare paths (absolute realpath, relative url path)
    /*size_t root_len = strlen(root);
    if (strncmp(real_path, root, root_len) != 0 ||
        (real_path[root_len] != '/' && real_path[root_len] != '\0')) {
        http_error(p, 403, "Forbidden");
        return;
    }*/

    struct stat st;
    if (stat(real_path, &st) < 0) {
        http_error(p, 404, "Not Found");
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        char index_path[PATH_MAX];
        snprintf(index_path, sizeof(index_path), "%s/index.html", real_path);
        if (stat(index_path, &st) < 0) {
            http_error(p, 404, "Not Found");
            return;
        }
        strncpy(real_path, index_path, sizeof(real_path) - 1);
        real_path[sizeof(real_path) - 1] = '\0';
    }
    if (!S_ISREG(st.st_mode)) {
        http_error(p, 403, "Forbidden");
        return;
    }
    int file_fd = open(real_path, O_RDONLY);
    if (file_fd < 0) {
        http_error(p, 500, "Internal Server Error");
        return;
    }
    const char *mime = get_mime_type(real_path);
    struct http_response resp = {
        .status_code = 200,
        .reason_phrase = "OK",
        .body = NULL,
        .body_len = st.st_size
    };
    struct http_header ct = {.key = "Content-Type", .value = (char *)mime};
    shputs(resp.headers, ct);
    struct http_header server = {.key = "Server", .value = "NanoServer/0.1"};
    shputs(resp.headers, server);
    http_add_connection_header(&resp, true);
    char resp_buf[2048];
    size_t resp_len = http_build_response(&resp, resp_buf, sizeof(resp_buf));
    shfree(resp.headers);
    if (resp_len == 0) {
        close(file_fd);
        http_error(p, 500, "Internal Server Error");
        return;
    }
    socket_write(p->fd, resp_buf, resp_len);

    // Setup async sending
    cd->sending_body = true;
    cd->send_file_fd = file_fd;
    cd->send_offset = 0;
    cd->send_remaining = st.st_size;
    cd->use_sendfile = (cd->ssl == NULL);  // Use sendfile only if no SSL

    cd->send_buffer = malloc(CHUNK_SIZE);
    if (!cd->send_buffer) {
        http_error(p, 500, "Internal Server Error");
        close(file_fd);
        return;
    }
    cd->send_buf_len = 0;
    cd->send_buf_pos = 0;
    // Initial attempt to send
    resume_send(cd->loopfd, cd->fd);
	//printf("event_mod WAIT FOR WRITE\n");
	//event_mod(cd->loopfd, p->fd, EV_WRITE);
	/*
    if (cd->send_remaining == 0) {
        // Finished immediately (small file or full send)
        cleanup_send_state(cd);
        cd->sending_body = false;
    } else {
        // Need to wait for writability
		printf("event_mod WAIT FOR WRITE\n");
        event_mod(cd->loopfd, p->fd, EV_WRITE );
		fprintf(stderr, "event_mod WAIT FOR WRITE on fd %d (remaining %zu)\n", p->fd, cd->send_remaining);
    }
	*/
}




static inline void http_dispatcher(http_p *p, struct http_request *req, struct client_data *info) {
    char action[512];
    snprintf(action, sizeof(action), "%s %s %s", req->method ? req->method : "", req->uri ? req->uri : "", req->version ? req->version : "");

    bool keep_alive = http_should_keep_alive(req);
	//printf("keep_alive = %s\n", keep_alive?"TRUE":"FALSE");

    ptrdiff_t base_idx = shgeti(base_handlers, info->listen_uri);
    if (base_idx >= 0) {
        struct path_entry *paths = base_handlers[base_idx].value;
        char *best_key = NULL;
        size_t best_len = 0;
        http_handler_t best_h = NULL;
        for (ptrdiff_t j = 0; j < shlen(paths); ++j) {
            char *key = paths[j].key;
            size_t klen = strlen(key);
            bool match;
            if (key[klen - 1] == '/') {
                match = (strncmp(req->uri, key, klen) == 0);
            } else {
                match = (strcmp(req->uri, key) == 0);
            }
            if (match && klen > best_len) {
                best_len = klen;
                best_key = key;
                best_h = paths[j].value;
            }
        }
        if (best_h) {
            info->matched_prefix = best_key;
            best_h(p, req, info);
            default_access_log(&info->info, action, 0, 0);
        }
		return;
    }

	char *best_key = NULL;
	size_t best_len = 0;
	http_handler_t best_h = NULL;
	for (ptrdiff_t j = 0; j < shlen(global_http_handlers); ++j) {
		char *key = global_http_handlers[j].key;
		size_t klen = strlen(key);
		bool match;
		if (key[klen - 1] == '/') {
			match = (strncmp(req->uri, key, klen) == 0);
		} else {
			match = (strcmp(req->uri, key) == 0);
		}
		if (match && klen > best_len) {
			best_len = klen;
			best_key = key;
			best_h = global_http_handlers[j].value;
		}
	}
	if (best_h) {
		info->matched_prefix = best_key;
		best_h(p, req, info);
		default_access_log(&info->info, action, 0, 0);
	} else {
		info->matched_prefix = NULL;
		default_http_handler(p, req, info);
		default_access_log(&info->info, action, 0, 0);
	}

    // Post-process: add Connection header and decide on persistence
    // Note: This assumes the handler has already sent the response via http_ok/http_error.
    // Since handlers build/send immediately, we can't modify the response here.
    // Instead, rely on handlers to use keep-alive if needed, or add to next step.

    // For persistence: reset parser if keep-alive, else close
    if (keep_alive) {
        http_parser_reset(p);
        // Optionally: update event for next read (your loop should already re-arm if not closed)
    } else if (!info->sending_body || info->send_remaining == 0) {
        conn_del(p->fd);
		// FIXME: We don't have the loopfd... soooo maybe fix later
        //if (handlers.on_disconnect) handlers.on_disconnect(loopfd, fd);  // loopfd from outer scope
    }
}

static inline void resume_send(int loopfd, int fd) {
	int idx = get_conn(fd);
    if (idx == -1) return;
    struct client_data *cd = &clients[idx];

    if (!cd->sending_body || cd->send_remaining == 0) return;
    //printf("resume_send: sendfile=%s remaining=%zu    \r", cd->use_sendfile ? "TRUE" : "FALSE", cd->send_remaining);

    ssize_t sent = 0;
    if (cd->use_sendfile) {
#ifdef __APPLE__
        off_t len = cd->send_remaining;
        int ret = sendfile(cd->send_file_fd, cd->fd, cd->send_offset, &len, NULL, 0);
        sent = len;
        if (ret == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                my_on_error(cd->loopfd, cd->fd, errno, NULL);
                cleanup_send_state(cd);
                conn_del(cd->fd);
                return;
            }
            // For EAGAIN, proceed with sent = len (possibly 0 or partial)
        }
        // For success (ret == 0), sent = len == remaining
#else
        sent = sendfile(cd->fd, cd->send_file_fd, &cd->send_offset, cd->send_remaining);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                sent = 0;
                // Proceed
            } else {
                my_on_error(cd->loopfd, cd->fd, errno, NULL);
                cleanup_send_state(cd);
                conn_del(cd->fd);
                return;
            }
        }
#endif
    } else {
        if (cd->send_buf_pos == cd->send_buf_len) {
            ssize_t r = read(cd->send_file_fd, cd->send_buffer, CHUNK_SIZE);
            if (r <= 0) {
                if (r < 0) my_on_error(cd->loopfd, cd->fd, errno, NULL);
                cleanup_send_state(cd);
                return;
            }
            cd->send_buf_len = r;
            cd->send_buf_pos = 0;
            //printf("Buffered read: %zd bytes\n", r);
        }
        sent = socket_write(cd->fd, cd->send_buffer + cd->send_buf_pos, cd->send_buf_len - cd->send_buf_pos);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                sent = 0;
            } else {
                my_on_error(cd->loopfd, cd->fd, errno, NULL);
                cleanup_send_state(cd);
                conn_del(cd->fd);
                return;
            }
        }
        cd->send_buf_pos += sent;
        //printf("Buffered sent: %zd bytes\n", sent);
    }
    cd->bytes_written += sent;
    cd->send_remaining -= sent;
    cd->send_offset += sent;
    //printf("sent %zd, remaining now %zu\n", sent, cd->send_remaining);
    if (cd->send_remaining == 0) {
        cleanup_send_state(cd);
        event_mod(cd->loopfd, cd->fd, EV_READ);
        if (http_should_keep_alive(&cd->parser.req)) {
			//printf("http_parser_reset\n");
            http_parser_reset(&cd->parser);
        } else {
			//printf("conn_del\n");
            conn_del(cd->fd);
        }
    } else {
        event_mod(cd->loopfd, cd->fd, EV_WRITE);
    }
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
