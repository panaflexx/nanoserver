#define STRINGBUF_IMPLEMENTATION
#include "stringbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

int main(int argc, char *argv[]) {
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

    run_event_loop(loopfd, &ss, &handlers);

    hmfree(fd_to_index);
    return EXIT_SUCCESS;
}
