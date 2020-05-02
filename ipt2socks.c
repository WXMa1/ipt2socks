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

enum {
    OPT_ENABLE_TCP        = 0x01 << 0, /* enable tcp proxy */
    OPT_ENABLE_UDP        = 0x01 << 1, /* enable udp proxy */
    OPT_ENABLE_IPV4       = 0x01 << 2, /* enable ipv4 proxy */
    OPT_ENABLE_IPV6       = 0x01 << 3, /* enable ipv6 proxy */
    OPT_TCP_USE_REDIRECT  = 0x01 << 4, /* use REDIRECT instead of TPROXY (used by tcp) */
    OPT_ALWAYS_REUSE_PORT = 0x01 << 5, /* always enable SO_REUSEPORT (since linux 3.9+) */
};

#define IF_VERBOSE if (g_verbose)

#define TCP_SKBUFSIZE_MINIMUM 1024
#define TCP_SKBUFSIZE_DEFAULT 8192
#define TCP_SKBUFSIZE_MAXIMUM 65535

#define IPT2SOCKS_VERSION "ipt2socks v1.0.2 <https://github.com/zfl9/ipt2socks>"

typedef struct {
    evio_t   client_watcher; // .data: buffer
    evio_t   socks5_watcher; // .data: buffer
    uint16_t client_recvlen;
    uint16_t socks5_recvlen;
    uint16_t client_sendlen;
    uint16_t socks5_sendlen;
} tcp_context_t;

static void* run_event_loop(void *is_main_thread);

void tcp_tproxy_accept_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_socks5_connect_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_stream_recv_payload_cb(evloop_t *evloop, evio_t *watcher, int events);
void tcp_stream_send_payload_cb(evloop_t *evloop, evio_t *watcher, int events);

void udp_tproxy_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_connect_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_context_release_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_socks5_context_timeout_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_tproxy_context_release_cb(evloop_t *evloop, evio_t *watcher, int events);
void udp_tproxy_context_timeout_cb(evloop_t *evloop, evio_t *watcher, int events);

static bool     g_verbose    = false;
static uint8_t  g_options    = OPT_ENABLE_TCP | OPT_ENABLE_UDP | OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6;
static uint8_t  g_nthreads   = 1;
static uint32_t g_tcpbufsiz  = TCP_SKBUFSIZE_DEFAULT;
static uint16_t g_udpidlesec = 180;

static char      g_bind_ipstr4[IP4STRLEN] = IP4STR_LOOPBACK;
static char      g_bind_ipstr6[IP6STRLEN] = IP6STR_LOOPBACK;
static portno_t  g_bind_portno            = 60080;
static skaddr4_t g_bind_skaddr4           = {0};
static skaddr6_t g_bind_skaddr6           = {0};

static char      g_server_ipstr[IP6STRLEN] = {0};
static portno_t  g_server_portno           = 0;
static skaddr6_t g_server_skaddr           = {0};

static udp_socks5ctx_t *g_udp_socks5ctx_table                   = NULL;
static udp_tproxyctx_t *g_udp_tproxyctx_table                   = NULL;
static char             g_udp_ipstr_buffer[IP6STRLEN]           = {0};
static char             g_udp_dgram_buffer[UDP_DATAGRAM_MAXSIZ] = {0};
static char             g_udp_socks5_buffer[SOCKS5_HDR_MAXSIZE] = {0};

static socks5_authreq_t g_socks5_auth_request = {
    .version = SOCKS5_VERSION,
    .mlength = 1,
    .method = SOCKS5_METHOD_NOAUTH, /* noauth by default */
};

static char     g_socks5_usrpwd_request[SOCKS5_USRPWD_REQMAXLEN] = {0};
static uint16_t g_socks5_usrpwd_requestlen = 0;

static socks5_ipv4req_t g_socks5_udp4_request = {
    .version = SOCKS5_VERSION,
    .command = SOCKS5_COMMAND_UDPASSOCIATE,
    .reserved = 0,
    .addrtype = SOCKS5_ADDRTYPE_IPV4,
    .ipaddr4 = 0,
    .portnum = 0,
};

static socks5_ipv6req_t g_socks5_udp6_request = {
    .version = SOCKS5_VERSION,
    .command = SOCKS5_COMMAND_UDPASSOCIATE,
    .reserved = 0,
    .addrtype = SOCKS5_ADDRTYPE_IPV6,
    .ipaddr6 = {0},
    .portnum = 0,
};

static void print_command_help(void) {
    printf("usage: ipt2socks <options...>. the existing options are as follows:\n"
           " -s, --server-addr <addr>           socks5 server ip address, <required>\n"
           " -p, --server-port <port>           socks5 server port number, <required>\n"
           " -a, --auth-username <user>         username for socks5 authentication\n"
           " -k, --auth-password <passwd>       password for socks5 authentication\n"
           " -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1\n"
           " -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1\n"
           " -l, --listen-port <port>           listen port number, default: 60080\n"
           " -j, --thread-nums <num>            number of worker threads, default: 1\n"
           " -n, --nofile-limit <num>           set nofile limit, maybe need root priv\n"
           " -o, --udp-timeout <sec>            udp socket idle timeout, default: 300\n"
           " -c, --cache-size <size>            max size of udp lrucache, default: 256\n"
           " -f, --buffer-size <size>           buffer size of tcp socket, default: 8192\n"
           " -u, --run-user <user>              run the ipt2socks with the specified user\n"
           " -G, --graceful                     gracefully close the tcp connection pair\n"
           " -R, --redirect                     use redirect instead of tproxy (for tcp)\n"
           " -T, --tcp-only                     listen tcp only, aka: disable udp proxy\n"
           " -U, --udp-only                     listen udp only, aka: disable tcp proxy\n"
           " -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy\n"
           " -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy\n"
           " -v, --verbose                      print verbose log, default: <disabled>\n"
           " -V, --version                      print ipt2socks version number and exit\n"
           " -h, --help                         print ipt2socks help information and exit\n"
    );
}

/* parsing command line arguments */
static void parse_command_args(int argc, char* argv[]) {
    const char *optstr = ":s:p:a:k:b:B:l:j:n:o:c:f:u:GRTU46vVh";
    const struct option options[] = {
        {"server-addr",   required_argument, NULL, 's'},
        {"server-port",   required_argument, NULL, 'p'},
        {"auth-username", required_argument, NULL, 'a'},
        {"auth-password", required_argument, NULL, 'k'},
        {"listen-addr4",  required_argument, NULL, 'b'},
        {"listen-addr6",  required_argument, NULL, 'B'},
        {"listen-port",   required_argument, NULL, 'l'},
        {"thread-nums",   required_argument, NULL, 'j'},
        {"nofile-limit",  required_argument, NULL, 'n'},
        {"udp-timeout",   required_argument, NULL, 'o'},
        {"cache-size",    required_argument, NULL, 'c'},
        {"buffer-size",   required_argument, NULL, 'f'},
        {"run-user",      required_argument, NULL, 'u'},
        {"graceful",      no_argument,       NULL, 'G'},
        {"redirect",      no_argument,       NULL, 'R'},
        {"tcp-only",      no_argument,       NULL, 'T'},
        {"udp-only",      no_argument,       NULL, 'U'},
        {"ipv4-only",     no_argument,       NULL, '4'},
        {"ipv6-only",     no_argument,       NULL, '6'},
        {"verbose",       no_argument,       NULL, 'v'},
        {"version",       no_argument,       NULL, 'V'},
        {"help",          no_argument,       NULL, 'h'},
        {NULL,            0,                 NULL,   0},
    };

    const char *opt_auth_username = NULL;
    const char *opt_auth_password = NULL;

    opterr = 0;
    int optindex = -1;
    int shortopt = -1;
    while ((shortopt = getopt_long(argc, argv, optstr, options, &optindex)) != -1) {
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
                g_server_portno = strtol(optarg, NULL, 10);
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
                opt_auth_username = optarg;
                break;
            case 'k':
                if (strlen(optarg) > SOCKS5_USRPWD_PWDMAXLEN) {
                    printf("[parse_command_args] socks5 password max length is 255: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                opt_auth_password = optarg;
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
                g_bind_portno = strtol(optarg, NULL, 10);
                if (g_bind_portno == 0) {
                    printf("[parse_command_args] invalid listen port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'j':
                g_nthreads = strtol(optarg, NULL, 10);
                if (g_nthreads == 0) {
                    printf("[parse_command_args] invalid number of worker threads: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'n':
                set_nofile_limit(strtol(optarg, NULL, 10));
                break;
            case 'o':
                g_udpidlesec = strtol(optarg, NULL, 10);
                if (g_udpidlesec == 0) {
                    printf("[parse_command_args] invalid udp socket idle timeout: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'c':
                if (strtol(optarg, NULL, 10) == 0) {
                    printf("[parse_command_args] invalid maxsize of udp lrucache: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                lrucache_set_maxsize(strtol(optarg, NULL, 10));
                break;
            case 'f':
                g_tcpbufsiz = strtol(optarg, NULL, 10);
                if (g_tcpbufsiz < TCP_SKBUFSIZE_MINIMUM) {
                    printf("[parse_command_args] buffer should have at least 1024B: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'u':
                run_as_user(optarg, argv);
                break;
            case 'R':
                g_options |= OPT_TCP_USE_REDIRECT;
                strcpy(g_bind_ipstr4, IP4STR_WILDCARD);
                strcpy(g_bind_ipstr6, IP6STR_WILDCARD);
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

    if (strlen(g_server_ipstr) == 0) {
        printf("[parse_command_args] missing option: '-s/--server-addr'\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (g_server_portno == 0) {
        printf("[parse_command_args] missing option: '-p/--server-port'\n");
        goto PRINT_HELP_AND_EXIT;
    }

    if (!(g_options & (OPT_ENABLE_TCP | OPT_ENABLE_UDP))) {
        printf("[parse_command_args] both tcp and udp are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!(g_options & (OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6))) {
        printf("[parse_command_args] both ipv4 and ipv6 are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }

    if (opt_auth_username && !opt_auth_password) {
        printf("[parse_command_args] username specified, but password is not provided\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!opt_auth_username && opt_auth_password) {
        printf("[parse_command_args] password specified, but username is not provided\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (opt_auth_username && opt_auth_password) {
        /* change auth method to usrpwd */
        g_socks5_auth_request.method = SOCKS5_METHOD_USRPWD;

        /* socks5-usrpwd-request version */
        socks5_usrpwdreq_t *usrpwdreq = (void *)g_socks5_usrpwd_request;
        usrpwdreq->version = SOCKS5_USRPWD_VERSION;

        /* socks5-usrpwd-request usernamelen */
        uint8_t *usrlenptr = (void *)usrpwdreq + 1;
        *usrlenptr = strlen(opt_auth_username);

        /* socks5-usrpwd-request usernamestr */
        char *usrbufptr = (void *)usrlenptr + 1;
        memcpy(usrbufptr, opt_auth_username, *usrlenptr);

        /* socks5-usrpwd-request passwordlen */
        uint8_t *pwdlenptr = (void *)usrbufptr + *usrlenptr;
        *pwdlenptr = strlen(opt_auth_password);

        /* socks5-usrpwd-request passwordstr */
        char *pwdbufptr = (void *)pwdlenptr + 1;
        memcpy(pwdbufptr, opt_auth_password, *pwdlenptr);

        /* socks5-usrpwd-request total_length */
        g_socks5_usrpwd_requestlen = 1 + 1 + *usrlenptr + 1 + *pwdlenptr;
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

/* main entry */
int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    parse_command_args(argc, argv);

    LOGINF("[main] server address: %s#%hu", g_server_ipstr, g_server_portno);
    if (g_options & OPT_ENABLE_IPV4) LOGINF("[main] listen address: %s#%hu", g_bind_ipstr4, g_bind_portno);
    if (g_options & OPT_ENABLE_IPV6) LOGINF("[main] listen address: %s#%hu", g_bind_ipstr6, g_bind_portno);
    LOGINF("[main] number of worker threads: %hhu", g_nthreads);
    LOGINF("[main] udp socket idle timeout: %hu", g_udpidlesec);
    LOGINF("[main] udp cache maximum size: %hu", lrucache_get_maxsize());
    LOGINF("[main] tcp socket buffer size: %u", g_tcpbufsiz);
    if (g_options & OPT_ENABLE_TCP) LOGINF("[main] enable tcp transparent proxy");
    if (g_options & OPT_ENABLE_UDP) LOGINF("[main] enable udp transparent proxy");
    if (g_options & OPT_TCP_USE_REDIRECT) LOGINF("[main] use redirect instead of tproxy");
    IF_VERBOSE LOGINF("[main] verbose mode (affect performance)");

    for (int i = 0; i < g_nthreads - 1; ++i) {
        if (pthread_create(&(pthread_t){0}, NULL, run_event_loop, NULL)) {
            LOGERR("[main] failed to create thread: (%d) %s", errno, my_strerror(errno));
            return errno;
        }
    }
    run_event_loop((void *)1); /* blocking here */

    return 0;
}

/* event loop */
static void* run_event_loop(void *is_main_thread) {
    // TODO
    return NULL;
}
