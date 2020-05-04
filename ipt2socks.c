#define _GNU_SOURCE
#include "logutils.h"
#include "lrucache.h"
#include "netutils.h"
#include "protocol.h"
#include "libev/ev.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#undef _GNU_SOURCE

#define TCP_SKBUFSIZE_MINIMUM 1024
#define TCP_SKBUFSIZE_DEFAULT 8192

#define IF_VERBOSE if (g_verbose)

#define IPT2SOCKS_VERSION "ipt2socks v1.1.0 <https://github.com/zfl9/ipt2socks>"

enum {
    OPT_ENABLE_TCP         = 0x01 << 0, // enable tcp proxy
    OPT_ENABLE_UDP         = 0x01 << 1, // enable udp proxy
    OPT_ENABLE_IPV4        = 0x01 << 2, // enable ipv4 proxy
    OPT_ENABLE_IPV6        = 0x01 << 3, // enable ipv6 proxy
    OPT_TCP_USE_REDIRECT   = 0x01 << 4, // use redirect instead of tproxy (used by tcp)
    OPT_ALWAYS_REUSE_PORT  = 0x01 << 5, // always enable so_reuseport (since linux 3.9+)
    OPT_ENABLE_TFO_ACCEPT  = 0x01 << 6, // enable tcp_fastopen for listen socket (server tfo)
    OPT_ENABLE_TFO_CONNECT = 0x01 << 7, // enable tcp_fastopen for connect socket (client tfo)
};

typedef struct {
    evio_t   client_watcher; // .data: buffer
    evio_t   socks5_watcher; // .data: buffer
    uint16_t client_nrecv;
    uint16_t client_nsend;
    uint16_t socks5_nrecv;
    uint16_t socks5_nsend;
} tcp_context_t;

static void* run_event_loop(void *is_main_thread);

static void tcp_tproxy_accept_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_connect_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_stream_payload_forward_cb(evloop_t *evloop, evio_t *watcher, int revents);

static void udp_tproxy_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_connect_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_context_timeout_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_tproxy_context_timeout_cb(evloop_t *evloop, evio_t *watcher, int revents);

static bool     g_verbose  = false;
static uint16_t g_options  = OPT_ENABLE_TCP | OPT_ENABLE_UDP | OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6;
static uint8_t  g_nthreads = 1;

static char      g_bind_ipstr4[IP4STRLEN] = IP4STR_LOOPBACK;
static char      g_bind_ipstr6[IP6STRLEN] = IP6STR_LOOPBACK;
static portno_t  g_bind_portno            = 60080;
static skaddr4_t g_bind_skaddr4           = {0};
static skaddr6_t g_bind_skaddr6           = {0};

static char      g_server_ipstr[IP6STRLEN] = "127.0.0.1";
static portno_t  g_server_portno           = 1080;
static skaddr6_t g_server_skaddr           = {0};

static uint8_t  g_tcp_syncnt_max  = 0; // 0: use default syncnt
static uint16_t g_tcp_buffer_size = TCP_SKBUFSIZE_DEFAULT; // maxsize: 65535

static uint16_t         g_udp_idletimeout_sec                   = 180;
static udp_socks5ctx_t *g_udp_socks5ctx_table                   = NULL;
static udp_tproxyctx_t *g_udp_tproxyctx_table                   = NULL;
static char             g_udp_dgram_buffer[UDP_DATAGRAM_MAXSIZ] = {0};

static void print_command_help(void) {
    printf("usage: ipt2socks <options...>. the existing options are as follows:\n"
           " -s, --server-addr <addr>           socks5 server ip, default: 127.0.0.1\n"
           " -p, --server-port <port>           socks5 server port, default: 1080\n"
           " -a, --auth-username <user>         username for socks5 authentication\n"
           " -k, --auth-password <passwd>       password for socks5 authentication\n"
           " -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1\n"
           " -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1\n"
           " -l, --listen-port <port>           listen port number, default: 60080\n"
           " -f, --buffer-size <size>           tcp socket recv bufsize, default: 8192\n"
           " -S, --tcp-syncnt <cnt>             change the number of tcp syn retransmits\n"
           " -c, --cache-size <size>            udp context cache maxsize, default: 256\n"
           " -o, --udp-timeout <sec>            udp context idle timeout, default: 180\n"
           " -j, --thread-nums <num>            number of the worker threads, default: 1\n"
           " -n, --nofile-limit <num>           set nofile limit, may need root privilege\n"
           " -u, --run-user <user>              run as the given user, need root privilege\n"
           " -T, --tcp-only                     listen tcp only, aka: disable udp proxy\n"
           " -U, --udp-only                     listen udp only, aka: disable tcp proxy\n"
           " -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy\n"
           " -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy\n"
           " -R, --redirect                     use redirect instead of tproxy for tcp\n"
           " -r, --reuse-port                   enable so_reuseport for single thread\n"
           " -w, --tfo-accept                   enable tcp_fastopen for server socket\n"
           " -W, --tfo-connect                  enable tcp_fastopen for client socket\n"
           " -v, --verbose                      print verbose log, affect performance\n"
           " -V, --version                      print ipt2socks version number and exit\n"
           " -h, --help                         print ipt2socks help information and exit\n"
    );
}

static void parse_command_args(int argc, char* argv[]) {
    opterr = 0; /* disable errmsg print, can get error by retval '?' */
    const char *optstr = ":s:p:a:k:b:B:l:f:S:c:o:j:n:u:TU46RrwWvVh";
    const struct option options[] = {
        {"server-addr",   required_argument, NULL, 's'},
        {"server-port",   required_argument, NULL, 'p'},
        {"auth-username", required_argument, NULL, 'a'},
        {"auth-password", required_argument, NULL, 'k'},
        {"listen-addr4",  required_argument, NULL, 'b'},
        {"listen-addr6",  required_argument, NULL, 'B'},
        {"listen-port",   required_argument, NULL, 'l'},
        {"buffer-size",   required_argument, NULL, 'f'},
        {"tcp-syncnt",    required_argument, NULL, 'S'},
        {"cache-size",    required_argument, NULL, 'c'},
        {"udp-timeout",   required_argument, NULL, 'o'},
        {"thread-nums",   required_argument, NULL, 'j'},
        {"nofile-limit",  required_argument, NULL, 'n'},
        {"run-user",      required_argument, NULL, 'u'},
        {"tcp-only",      no_argument,       NULL, 'T'},
        {"udp-only",      no_argument,       NULL, 'U'},
        {"ipv4-only",     no_argument,       NULL, '4'},
        {"ipv6-only",     no_argument,       NULL, '6'},
        {"redirect",      no_argument,       NULL, 'R'},
        {"reuse-port",    no_argument,       NULL, 'r'},
        {"tfo-accept",    no_argument,       NULL, 'w'},
        {"tfo-connect",   no_argument,       NULL, 'W'},
        {"verbose",       no_argument,       NULL, 'v'},
        {"version",       no_argument,       NULL, 'V'},
        {"help",          no_argument,       NULL, 'h'},
        {NULL,            0,                 NULL,   0},
    };

    const char *optval_auth_username = NULL;
    const char *optval_auth_password = NULL;

    int shortopt = -1;
    while ((shortopt = getopt_long(argc, argv, optstr, options, NULL)) != -1) {
        switch (shortopt) {
            case 's':
                if (strlen(optarg) + 1 > IP6STRLEN) {
                    printf("[parse_command_args] ip address max length is 45: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                if (get_ipstr_family(optarg) == -1) {
                    printf("[parse_command_args] invalid server ip address: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_server_ipstr, optarg);
                break;
            case 'p':
                if (strlen(optarg) + 1 > PORTSTRLEN) {
                    printf("[parse_command_args] port number max length is 5: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_server_portno = strtoul(optarg, NULL, 10);
                if (g_server_portno == 0) {
                    printf("[parse_command_args] invalid server port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'a':
                if (strlen(optarg) > SOCKS5_USRPWD_USRMAXLEN) {
                    printf("[parse_command_args] socks5 username max length is 255: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                optval_auth_username = optarg;
                break;
            case 'k':
                if (strlen(optarg) > SOCKS5_USRPWD_PWDMAXLEN) {
                    printf("[parse_command_args] socks5 password max length is 255: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                optval_auth_password = optarg;
                break;
            case 'b':
                if (strlen(optarg) + 1 > IP4STRLEN) {
                    printf("[parse_command_args] ipv4 address max length is 15: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                if (get_ipstr_family(optarg) != AF_INET) {
                    printf("[parse_command_args] invalid listen ipv4 address: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_bind_ipstr4, optarg);
                break;
            case 'B':
                if (strlen(optarg) + 1 > IP6STRLEN) {
                    printf("[parse_command_args] ipv6 address max length is 45: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                if (get_ipstr_family(optarg) != AF_INET6) {
                    printf("[parse_command_args] invalid listen ipv6 address: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_bind_ipstr6, optarg);
                break;
            case 'l':
                if (strlen(optarg) + 1 > PORTSTRLEN) {
                    printf("[parse_command_args] port number max length is 5: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_bind_portno = strtoul(optarg, NULL, 10);
                if (g_bind_portno == 0) {
                    printf("[parse_command_args] invalid listen port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'f':
                g_tcp_buffer_size = strtoul(optarg, NULL, 10);
                if (g_tcp_buffer_size < TCP_SKBUFSIZE_MINIMUM) {
                    printf("[parse_command_args] buffer should have at least 1024B: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'S':
                g_tcp_syncnt_max = strtoul(optarg, NULL, 10);
                if (g_tcp_syncnt_max == 0) {
                    printf("[parse_command_args] invalid number of syn retransmits: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'c':
                if (strtoul(optarg, NULL, 10) == 0) {
                    printf("[parse_command_args] invalid maxsize of udp lrucache: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                lrucache_set_maxsize(strtoul(optarg, NULL, 10));
                break;
            case 'o':
                g_udp_idletimeout_sec = strtoul(optarg, NULL, 10);
                if (g_udp_idletimeout_sec == 0) {
                    printf("[parse_command_args] invalid udp socket idle timeout: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'j':
                g_nthreads = strtoul(optarg, NULL, 10);
                if (g_nthreads == 0) {
                    printf("[parse_command_args] invalid number of worker threads: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'n':
                set_nofile_limit(strtoul(optarg, NULL, 10));
                break;
            case 'u':
                run_as_user(optarg, argv);
                break;
            case 'T':
                g_options &= ~OPT_ENABLE_UDP;
                break;
            case 'U':
                g_options &= ~OPT_ENABLE_TCP;
                break;
            case '4':
                g_options &= ~OPT_ENABLE_IPV6;
                break;
            case '6':
                g_options &= ~OPT_ENABLE_IPV4;
                break;
            case 'R':
                g_options |= OPT_TCP_USE_REDIRECT;
                strcpy(g_bind_ipstr4, IP4STR_WILDCARD);
                strcpy(g_bind_ipstr6, IP6STR_WILDCARD);
                break;
            case 'r':
                g_options |= OPT_ALWAYS_REUSE_PORT;
                break;
            case 'w':
                g_options |= OPT_ENABLE_TFO_ACCEPT;
                break;
            case 'W':
                g_options |= OPT_ENABLE_TFO_CONNECT;
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'V':
                printf(IPT2SOCKS_VERSION"\n");
                exit(0);
            case 'h':
                print_command_help();
                exit(0);
            case ':':
                printf("[parse_command_args] missing optarg: '%s'\n", argv[optind - 1]);
                goto PRINT_HELP_AND_EXIT;
            case '?':
                if (optopt) {
                    printf("[parse_command_args] unknown option: '-%c'\n", optopt);
                } else {
                    char *longopt = argv[optind - 1];
                    char *equalsign = strchr(longopt, '=');
                    if (equalsign) *equalsign = 0;
                    printf("[parse_command_args] unknown option: '%s'\n", longopt);
                }
                goto PRINT_HELP_AND_EXIT;
        }
    }

    if (!(g_options & (OPT_ENABLE_TCP | OPT_ENABLE_UDP))) {
        printf("[parse_command_args] both tcp and udp are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!(g_options & (OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6))) {
        printf("[parse_command_args] both ipv4 and ipv6 are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }

    if (optval_auth_username && !optval_auth_password) {
        printf("[parse_command_args] username specified, but password is not provided\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!optval_auth_username && optval_auth_password) {
        printf("[parse_command_args] password specified, but username is not provided\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (optval_auth_username && optval_auth_password) {
        socks5_usrpwd_request_make(optval_auth_username, optval_auth_password);
    }

    if (!(g_options & OPT_ENABLE_TCP)) g_nthreads = 1;

    build_socket_addr(AF_INET, &g_bind_skaddr4, g_bind_ipstr4, g_bind_portno);
    build_socket_addr(AF_INET6, &g_bind_skaddr6, g_bind_ipstr6, g_bind_portno);
    build_socket_addr(get_ipstr_family(g_server_ipstr), &g_server_skaddr, g_server_ipstr, g_server_portno);
    return;

PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    parse_command_args(argc, argv);

    LOGINF("[main] server address: %s#%hu", g_server_ipstr, g_server_portno);
    if (g_options & OPT_ENABLE_IPV4) LOGINF("[main] listen address: %s#%hu", g_bind_ipstr4, g_bind_portno);
    if (g_options & OPT_ENABLE_IPV6) LOGINF("[main] listen address: %s#%hu", g_bind_ipstr6, g_bind_portno);
    LOGINF("[main] tcp socket buffer size: %hu", g_tcp_buffer_size);
    if (g_tcp_syncnt_max) LOGINF("[main] max number of syn retries: %hhu", g_tcp_syncnt_max);
    LOGINF("[main] udp cache maximum size: %hu", lrucache_get_maxsize());
    LOGINF("[main] udp socket idle timeout: %hu", g_udp_idletimeout_sec);
    LOGINF("[main] number of worker threads: %hhu", g_nthreads);
    if (g_options & OPT_ENABLE_TCP) LOGINF("[main] enable tcp transparent proxy");
    if (g_options & OPT_ENABLE_UDP) LOGINF("[main] enable udp transparent proxy");
    if (g_options & OPT_TCP_USE_REDIRECT) LOGINF("[main] use redirect instead of tproxy");
    if (g_options & OPT_ALWAYS_REUSE_PORT) LOGINF("[main] always enable reuseport feature");
    if (g_options & OPT_ENABLE_TFO_ACCEPT) LOGINF("[main] enable tfo for tcp server socket");
    if (g_options & OPT_ENABLE_TFO_CONNECT) LOGINF("[main] enable tfo for tcp client socket");
    IF_VERBOSE LOGINF("[main] verbose mode (affect performance)");

    for (int i = 0; i < g_nthreads - 1; ++i) {
        if (pthread_create(&(pthread_t){0}, NULL, run_event_loop, NULL)) {
            LOGERR("[main] create worker thread: %s", my_strerror(errno));
            return errno;
        }
    }
    run_event_loop((void *)1);

    return 0;
}

static void* run_event_loop(void *is_main_thread) {
    evloop_t *evloop = ev_loop_new(0);

    if (g_options & OPT_ENABLE_TCP) {
        bool is_tproxy = !(g_options & OPT_TCP_USE_REDIRECT);
        bool is_tfo_accept = g_options & OPT_ENABLE_TFO_ACCEPT;
        bool is_reuse_port = g_nthreads > 1 || (g_options & OPT_ALWAYS_REUSE_PORT);

        if (g_options & OPT_ENABLE_IPV4) {
            int sockfd = new_tcp_listen_sockfd(AF_INET, is_tproxy, is_reuse_port, is_tfo_accept);

            if (bind(sockfd, (void *)&g_bind_skaddr4, sizeof(skaddr4_t)) < 0) {
                LOGERR("[run_event_loop] bind tcp4 address: %s", my_strerror(errno));
                exit(errno);
            }
            if (listen(sockfd, SOMAXCONN) < 0) {
                LOGERR("[run_event_loop] listen tcp4 socket: %s", my_strerror(errno));
                exit(errno);
            }

            evio_t *watcher = malloc(sizeof(*watcher));
            watcher->data = (void *)1; /* indicates it is ipv4 */
            ev_io_init(watcher, tcp_tproxy_accept_cb, sockfd, EV_READ);
            ev_io_start(evloop, watcher);
        }

        if (g_options & OPT_ENABLE_IPV6) {
            int sockfd = new_tcp_listen_sockfd(AF_INET6, is_tproxy, is_reuse_port, is_tfo_accept);

            if (bind(sockfd, (void *)&g_bind_skaddr6, sizeof(skaddr6_t)) < 0) {
                LOGERR("[run_event_loop] bind tcp6 address: %s", my_strerror(errno));
                exit(errno);
            }
            if (listen(sockfd, SOMAXCONN) < 0) {
                LOGERR("[run_event_loop] listen tcp6 socket: %s", my_strerror(errno));
                exit(errno);
            }

            evio_t *watcher = malloc(sizeof(*watcher));
            watcher->data = NULL; /* indicates it not ipv4 */
            ev_io_init(watcher, tcp_tproxy_accept_cb, sockfd, EV_READ);
            ev_io_start(evloop, watcher);
        }
    }

    if ((g_options & OPT_ENABLE_UDP) && is_main_thread) {
        if (g_options & OPT_ENABLE_IPV4) {
            int sockfd = new_udp_tprecv_sockfd(AF_INET);

            if (bind(sockfd, (void *)&g_bind_skaddr4, sizeof(skaddr4_t)) < 0) {
                LOGERR("[run_event_loop] bind udp4 address: %s", my_strerror(errno));
                exit(errno);
            }

            evio_t *watcher = malloc(sizeof(*watcher));
            watcher->data = (void *)1; /* indicates it is ipv4 */
            ev_io_init(watcher, udp_tproxy_recvmsg_cb, sockfd, EV_READ);
            ev_io_start(evloop, watcher);
        }

        if (g_options & OPT_ENABLE_IPV6) {
            int sockfd = new_udp_tprecv_sockfd(AF_INET6);

            if (bind(sockfd, (void *)&g_bind_skaddr6, sizeof(skaddr6_t)) < 0) {
                LOGERR("[run_event_loop] bind udp6 address: %s", my_strerror(errno));
                exit(errno);
            }

            evio_t *watcher = malloc(sizeof(*watcher));
            watcher->data = NULL; /* indicates it not ipv4 */
            ev_io_init(watcher, udp_tproxy_recvmsg_cb, sockfd, EV_READ);
            ev_io_start(evloop, watcher);
        }
    }

    ev_run(evloop, 0);
    return NULL;
}

static void tcp_tproxy_accept_cb(evloop_t *evloop, evio_t *accept_watcher, int revents __attribute__((unused))) {
    bool isipv4 = accept_watcher->data;
    skaddr6_t skaddr; char ipstr[IP6STRLEN]; portno_t portno;

    int client_sockfd = -1;
    if (!tcp_accept(accept_watcher->fd, &client_sockfd, &skaddr)) {
        LOGERR("[tcp_tproxy_accept_cb] accept tcp%s socket: %s", isipv4 ? "4" : "6", my_strerror(errno));
        return;
    }
    if (client_sockfd < 0) return;
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[tcp_tproxy_accept_cb] source socket address: %s#%hu", ipstr, portno);
    }

    if (!get_tcp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, client_sockfd, &skaddr, !(g_options & OPT_TCP_USE_REDIRECT))) {
        tcp_close_by_rst(client_sockfd);
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[tcp_tproxy_accept_cb] target socket address: %s#%hu", ipstr, portno);
    }

    int socks5_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);

    const void *tfo_data = (g_options & OPT_ENABLE_TFO_CONNECT) ? &g_socks5_auth_request : NULL;
    uint16_t tfo_datalen = (g_options & OPT_ENABLE_TFO_CONNECT) ? sizeof(socks5_authreq_t) : 0;
    ssize_t tfo_nsend = -1; /* if tfo connect succeed: tfo_nsend >= 0 */

    if (!tcp_connect(socks5_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, &tfo_nsend)) {
        LOGERR("[tcp_tproxy_accept_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, my_strerror(errno));
        tcp_close_by_rst(client_sockfd);
        close(socks5_sockfd);
        return;
    }

    if (tfo_nsend >= 0) {
        IF_VERBOSE LOGINF("[tcp_tproxy_accept_cb] tfo connect to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, tfo_nsend);
    } else {
        IF_VERBOSE LOGINF("[tcp_tproxy_accept_cb] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
    }

    tcp_context_t *context = malloc(sizeof(*context));
    context->client_watcher.data = malloc(g_tcp_buffer_size);
    context->socks5_watcher.data = malloc(g_tcp_buffer_size);

    /* if (watcher->events & EV_CUSTOM); then it is client watcher; fi */
    ev_io_init(&context->client_watcher, tcp_stream_payload_forward_cb, client_sockfd, EV_READ | EV_CUSTOM);

    if (tfo_nsend >= 0 && (size_t)tfo_nsend >= tfo_datalen) {
        ev_io_init(&context->socks5_watcher, tcp_socks5_recv_authresp_cb, socks5_sockfd, EV_READ);
        tfo_nsend = 0; /* reset to zero for next send */
    } else {
        ev_io_init(&context->socks5_watcher, tfo_nsend >= 0 ? tcp_socks5_send_authreq_cb : tcp_socks5_connect_cb, socks5_sockfd, EV_WRITE);
        tfo_nsend = tfo_nsend >= 0 ? tfo_nsend : 0;
    }
    ev_io_start(evloop, &context->socks5_watcher);

    context->socks5_nrecv = 0;
    context->socks5_nsend = (size_t)tfo_nsend;

    context->client_nsend = 0;
    context->client_nrecv = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    socks5_proxy_request_make(context->client_watcher.data, &skaddr);
}

static inline tcp_context_t* get_tcpctx_by_watcher(evio_t *watcher) {
    if (watcher->events & EV_CUSTOM) {
        return (void *)watcher - offsetof(tcp_context_t, client_watcher);
    } else {
        return (void *)watcher - offsetof(tcp_context_t, socks5_watcher);
    }
}

static inline void tcp_context_release(evloop_t *evloop, tcp_context_t *context, bool is_tcp_reset) {
    evio_t *client_watcher = &context->client_watcher;
    evio_t *socks5_watcher = &context->socks5_watcher;
    ev_io_stop(evloop, client_watcher);
    ev_io_stop(evloop, socks5_watcher);
    if (is_tcp_reset) {
        tcp_close_by_rst(client_watcher->fd);
        tcp_close_by_rst(socks5_watcher->fd);
    } else {
        close(client_watcher->fd);
        close(socks5_watcher->fd);
    }
    free(client_watcher->data);
    free(socks5_watcher->data);
    free(context);
}

static void tcp_socks5_connect_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_has_error(socks5_watcher->fd)) {
        LOGERR("[tcp_socks5_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, my_strerror(errno));
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    IF_VERBOSE LOGINF("[tcp_socks5_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);
    ev_set_cb(socks5_watcher, tcp_socks5_send_authreq_cb);
    ev_invoke(evloop, socks5_watcher, EV_WRITE);
}

/* return true if the request has been completely sent */
static bool tcp_socks5_send_request(const char *funcname, evloop_t *evloop, evio_t *socks5_watcher, const void *data, uint16_t datalen) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    size_t cur_nsend = context->socks5_nsend;
    if (!tcp_send_data(socks5_watcher->fd, data, datalen, &cur_nsend)) {
        LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, my_strerror(errno));
        tcp_context_release(evloop, context, true);
        return false;
    }
    if (context->socks5_nsend == cur_nsend) return false; // EAGAIN
    IF_VERBOSE LOGINF("[%s] send to %s#%hu, nsend:%zu", funcname, g_server_ipstr, g_server_portno, cur_nsend - context->socks5_nsend);
    context->socks5_nsend = cur_nsend;
    if (context->socks5_nsend >= datalen) {
        context->socks5_nsend = 0;
        return true;
    }
    return false;
}

/* return true if the response has been completely received */
static bool tcp_socks5_recv_response(const char *funcname, evloop_t *evloop, evio_t *socks5_watcher, void *data, uint16_t datalen) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    size_t cur_nrecv = context->socks5_nrecv; bool is_eof = false;
    if (!tcp_recv_data(socks5_watcher->fd, data, datalen, &cur_nrecv, &is_eof)) {
        LOGERR("[%s] recv from %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, my_strerror(errno));
        tcp_context_release(evloop, context, true);
        return false;
    }
    if (is_eof) {
        LOGERR("[%s] recv from %s#%hu: connection is closed", funcname, g_server_ipstr, g_server_portno);
        tcp_context_release(evloop, context, true);
        return false;
    }
    if (context->socks5_nrecv == cur_nrecv) return false; // EAGAIN
    IF_VERBOSE LOGINF("[%s] recv from %s#%hu, nrecv:%zu", funcname, g_server_ipstr, g_server_portno, cur_nrecv - context->socks5_nrecv);
    context->socks5_nrecv = cur_nrecv;
    if (context->socks5_nrecv >= datalen) {
        context->socks5_nrecv = 0;
        return true;
    }
    return false;
}

static void tcp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_send_request("tcp_socks5_send_authreq_cb", evloop, socks5_watcher, &g_socks5_auth_request, sizeof(socks5_authreq_t))) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, tcp_socks5_recv_authresp_cb, socks5_watcher->fd, EV_READ);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (!tcp_socks5_recv_response("tcp_socks5_recv_authresp_cb", evloop, socks5_watcher, socks5_watcher->data, sizeof(socks5_authresp_t))) {
        return;
    }
    if (!socks5_auth_response_check("tcp_socks5_recv_authresp_cb", socks5_watcher->data)) {
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, g_socks5_usrpwd_requestlen > 0 ? tcp_socks5_send_usrpwdreq_cb : tcp_socks5_send_proxyreq_cb, socks5_watcher->fd, EV_WRITE);
    ev_io_start(evloop, socks5_watcher);
}

static void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_send_request("tcp_socks5_send_usrpwdreq_cb", evloop, socks5_watcher, &g_socks5_usrpwd_request, g_socks5_usrpwd_requestlen)) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, tcp_socks5_recv_usrpwdresp_cb, socks5_watcher->fd, EV_READ);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (!tcp_socks5_recv_response("tcp_socks5_recv_usrpwdresp_cb", evloop, socks5_watcher, socks5_watcher->data, sizeof(socks5_usrpwdresp_t))) {
        return;
    }
    if (!socks5_usrpwd_response_check("tcp_socks5_recv_usrpwdresp_cb", socks5_watcher->data)) {
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_send_proxyreq_cb, socks5_watcher->fd, EV_WRITE);
    ev_io_start(evloop, socks5_watcher);
}

static void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_send_request("tcp_socks5_send_proxyreq_cb", evloop, socks5_watcher, context->client_watcher.data, context->client_nrecv)) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, tcp_socks5_recv_proxyresp_cb, socks5_watcher->fd, EV_READ);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (!tcp_socks5_recv_response("tcp_socks5_recv_proxyresp_cb", evloop, socks5_watcher, socks5_watcher->data, context->client_nrecv)) {
        return;
    }
    if (!socks5_proxy_response_check("tcp_socks5_recv_proxyresp_cb", socks5_watcher->data, context->client_nrecv == sizeof(socks5_ipv4resp_t))) {
        tcp_context_release(evloop, context, true);
        return;
    }
    ev_set_cb(socks5_watcher, tcp_stream_payload_forward_cb);
    ev_io_start(evloop, &context->client_watcher); /* already init */
}

static void tcp_stream_payload_forward_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_tproxy_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_connect_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_socks5_context_timeout_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}

static void udp_tproxy_context_timeout_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    // TODO
}
