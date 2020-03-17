#ifndef IPT2SOCKS_NETUTILS_H
#define IPT2SOCKS_NETUTILS_H

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

#define IP4BINLEN 4
#define IP6BINLEN 16

#define IP4STRLEN INET_ADDRSTRLEN
#define IP6STRLEN INET6_ADDRSTRLEN
#define PORTSTRLEN 6

#define IP4STR_LOOPBACK "127.0.0.1"
#define IP4STR_WILDCARD "0.0.0.0"
#define IP6STR_LOOPBACK "::1"
#define IP6STR_WILDCARD "::"

#define UDP_CTRLMESG_BUFSIZ 64
#define UDP_DATAGRAM_MAXSIZ 1472

typedef uint32_t ipaddr4_t;
typedef uint8_t  ipaddr6_t[16];

typedef union {
    ipaddr4_t ip4;
    ipaddr6_t ip6;
} ipaddr_t;

typedef uint16_t portno_t;

typedef struct {
    ipaddr_t ip;
    portno_t port;
} ip_port_t;

typedef struct sockaddr_in  skaddr4_t;
typedef struct sockaddr_in6 skaddr6_t;

int get_ipstr_family(const char *ipstr);
void build_socket_addr(int ipfamily, void *skaddr, const char *ipstr, portno_t portno);
void parse_socket_addr(const void *skaddr, char *ipstr, portno_t *portno);

void set_reuse_port(int sockfd);

bool get_tcp_orig_dstaddr(int ipfamily, int sockfd, void *dstaddr, bool is_tproxy);
bool get_udp_orig_dstaddr(int ipfamily, const struct msghdr *msg, void *dstaddr);

int new_tcp_listen_sockfd(int ipfamily, bool is_tproxy);
int new_tcp_connect_sockfd(int ipfamily);

int new_udp_tprecv_sockfd(int ipfamily);
int new_udp_tpsend_sockfd(int ipfamily);
int new_udp_normal_sockfd(int ipfamily);

void set_nofile_limit(size_t nofile);

void run_as_user(const char *username, char *const argv[]);

#endif
