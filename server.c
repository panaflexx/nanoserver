#define STRINGBUF_IMPLEMENTATION
#include "stringbuf.h"
#include <signal.h>
#include "socket_server.h"
#include "request.h"
#include <sys/resource.h>

struct base_entry *base_handlers = NULL;
struct path_entry *global_http_handlers = NULL;
struct socket_handler_entry *socket_handler_map = NULL;
LocationEntry *locations = NULL;

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN); // Ignoring SIGPIPE
    char *cert_file = NULL;
    char *key_file = NULL;
    int i = 1;
    int default_backlog = 1024; // Increased for better performance
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
        if (strlen(argv[i]) > MAX_URL_SIZE) {
            fprintf(stderr, "URI too long: %s\n", argv[i]);
            i++;
            continue;
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
        ptrdiff_t idx = shgeti(socket_handler_map, ss.sockets[k].uri);
        if (idx >= 0) {
            ss.sockets[k].socket_handler = socket_handler_map[idx].value;
        } else {
            ss.sockets[k].socket_handler = default_socket_handler;
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

	// Increase open file descriptor limit to handle more connections
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max = 10000;  // Set to a high value (adjust as needed)
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
            fprintf(stderr, "Warning: Failed to set rlimit: %s\n", strerror(errno));
        }
    } else {
        fprintf(stderr, "Warning: Failed to get rlimit: %s\n", strerror(errno));
    }

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

    addLocation("/", "html", 1001, 1001);
    addHandler("/", directory_handler);
    addHandler("/hello", hello_http_handler);

    run_event_loop(loopfd, &ss, &handlers);

    hmfree(fd_to_index);
    return EXIT_SUCCESS;
}
