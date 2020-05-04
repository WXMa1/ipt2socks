#define _GNU_SOURCE
#include "netutils.h"
#include "logutils.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#undef _GNU_SOURCE

#ifndef PATH_MAX
  #define PATH_MAX 4096
#endif

#ifndef SO_REUSEPORT
  #define SO_REUSEPORT 15
#endif

#ifndef TCP_FASTOPEN
  #define TCP_FASTOPEN 23
#endif

#ifndef MSG_FASTOPEN
  #define MSG_FASTOPEN 0x20000000
#endif

#ifndef IP_TRANSPARENT
  #define IP_TRANSPARENT 19
#endif

#ifndef IPV6_TRANSPARENT
  #define IPV6_TRANSPARENT 75
#endif

#ifndef IP_RECVORIGDSTADDR
  #define IP_RECVORIGDSTADDR 20
#endif

#ifndef IPV6_RECVORIGDSTADDR
  #define IPV6_RECVORIGDSTADDR 74
#endif

#ifndef SO_ORIGINAL_DST
  #define SO_ORIGINAL_DST 80
#endif

#ifndef IP6T_SO_ORIGINAL_DST
  #define IP6T_SO_ORIGINAL_DST 80
#endif

void set_nofile_limit(size_t nofile) {
    if (setrlimit(RLIMIT_NOFILE, &(struct rlimit){nofile, nofile}) < 0) {
        LOGERR("[set_nofile_limit] setrlimit(nofile, %zu): %s", nofile, my_strerror(errno));
    }
}

/* declare function prototype (openwrt?) */
int initgroups(const char *user, gid_t group);

void run_as_user(const char *username, char *argv[]) {
    if (geteuid() != 0) return; /* ignore if current user is not root */

    const struct passwd *userinfo = getpwnam(username);
    if (!userinfo) {
        LOGERR("[run_as_user] user:'%s' does not exist in this system", username);
        return;
    }

    if (userinfo->pw_uid == 0) return; /* ignore if target user is root */

    if (setgid(userinfo->pw_gid) < 0) {
        LOGERR("[run_as_user] change to gid:%u of user:'%s': %s", userinfo->pw_gid, userinfo->pw_name, my_strerror(errno));
        exit(errno);
    }

    if (initgroups(userinfo->pw_name, userinfo->pw_gid) < 0) {
        LOGERR("[run_as_user] initgroups(%u) of user:'%s': %s", userinfo->pw_gid, userinfo->pw_name, my_strerror(errno));
        exit(errno);
    }

    if (setuid(userinfo->pw_uid) < 0) {
        LOGERR("[run_as_user] change to uid:%u of user:'%s': %s", userinfo->pw_uid, userinfo->pw_name, my_strerror(errno));
        exit(errno);
    }

    static char execfile_abspath[PATH_MAX] = {0};
    if (readlink("/proc/self/exe", execfile_abspath, PATH_MAX - 1) < 0) {
        LOGERR("[run_as_user] readlink('/proc/self/exe'): %s", my_strerror(errno));
        exit(errno);
    }

    if (execv(execfile_abspath, argv) < 0) {
        LOGERR("[run_as_user] execv('%s', args): %s", execfile_abspath, my_strerror(errno));
        exit(errno);
    }
}

int get_ipstr_family(const char *ipstr) {
    if (!ipstr) return -1; /* invalid */
    ipaddr6_t ipaddr; /* save output */
    if (inet_pton(AF_INET, ipstr, &ipaddr) == 1) {
        return AF_INET;
    } else if (inet_pton(AF_INET6, ipstr, &ipaddr) == 1) {
        return AF_INET6;
    } else {
        return -1; /* invalid */
    }
}

void build_socket_addr(int family, void *skaddr, const char *ipstr, portno_t portno) {
    if (family == AF_INET) {
        skaddr4_t *addr = skaddr;
        addr->sin_family = AF_INET;
        inet_pton(AF_INET, ipstr, &addr->sin_addr);
        addr->sin_port = htons(portno);
    } else {
        skaddr6_t *addr = skaddr;
        addr->sin6_family = AF_INET6;
        inet_pton(AF_INET6, ipstr, &addr->sin6_addr);
        addr->sin6_port = htons(portno);
    }
}

void parse_socket_addr(const void *skaddr, char *ipstr, portno_t *portno) {
    if (((const skaddr4_t *)skaddr)->sin_family == AF_INET) {
        const skaddr4_t *addr = skaddr;
        inet_ntop(AF_INET, &addr->sin_addr, ipstr, IP4STRLEN);
        *portno = ntohs(addr->sin_port);
    } else {
        const skaddr6_t *addr = skaddr;
        inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, IP6STRLEN);
        *portno = ntohs(addr->sin6_port);
    }
}

static inline void set_non_block(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        LOGERR("[set_non_block] fcntl(%d, F_GETFL): %s", sockfd, my_strerror(errno));
        exit(errno);
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOGERR("[set_non_block] fcntl(%d, F_SETFL): %s", sockfd, my_strerror(errno));
        exit(errno);
    }
}

static inline void set_ipv6_only(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int)) < 0) {
        LOGERR("[set_ipv6_only] setsockopt(%d, IPV6_V6ONLY): %s", sockfd, my_strerror(errno));
    }
}

static inline void set_reuse_addr(int sockfd) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        LOGERR("[set_reuse_addr] setsockopt(%d, SO_REUSEADDR): %s", sockfd, my_strerror(errno));
    }
}

static inline void set_reuse_port(int sockfd) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0) {
        LOGERR("[set_reuse_port] setsockopt(%d, SO_REUSEPORT): %s", sockfd, my_strerror(errno));
    }
}

static inline void set_tcp_nodelay(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0) {
        LOGERR("[set_tcp_nodelay] setsockopt(%d, TCP_NODELAY): %s", sockfd, my_strerror(errno));
    }
}

static inline void set_tcp_quickack(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) < 0) {
        LOGERR("[set_tcp_quickack] setsockopt(%d, TCP_QUICKACK): %s", sockfd, my_strerror(errno));
    }
}

static inline void set_tfo_accept(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &(int){5}, sizeof(int)) < 0) {
        LOGERR("[set_tfo_accept] setsockopt(%d, TCP_FASTOPEN): %s", sockfd, my_strerror(errno));
    }
}

static inline void set_tcp_syncnt(int sockfd, int syncnt) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_SYNCNT, &syncnt, sizeof(int)) < 0) {
        LOGERR("[set_tcp_syncnt] setsockopt(%d, TCP_SYNCNT): %s", sockfd, my_strerror(errno));
    }
}

static inline void set_ip_transparent(int family, int sockfd) {
    if (family == AF_INET) {
        if (setsockopt(sockfd, IPPROTO_IP, IP_TRANSPARENT, &(int){1}, sizeof(int)) < 0) {
            LOGERR("[set_ip_transparent] setsockopt(%d, IP_TRANSPARENT): %s", sockfd, my_strerror(errno));
            exit(errno);
        }
    } else {
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_TRANSPARENT, &(int){1}, sizeof(int)) < 0) {
            LOGERR("[set_ip_transparent] setsockopt(%d, IPV6_TRANSPARENT): %s", sockfd, my_strerror(errno));
            exit(errno);
        }
    }
}

static inline void set_recv_origdstaddr(int family, int sockfd) {
    if (family == AF_INET) {
        if (setsockopt(sockfd, IPPROTO_IP, IP_RECVORIGDSTADDR, &(int){1}, sizeof(int)) < 0) {
            LOGERR("[set_recv_origdstaddr] setsockopt(%d, IP_RECVORIGDSTADDR): %s", sockfd, my_strerror(errno));
            exit(errno);
        }
    } else {
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &(int){1}, sizeof(int)) < 0) {
            LOGERR("[set_recv_origdstaddr] setsockopt(%d, IPV6_RECVORIGDSTADDR): %s", sockfd, my_strerror(errno));
            exit(errno);
        }
    }
}

static inline void setup_accepted_sockfd(int sockfd) {
    set_non_block(sockfd);
    set_tcp_nodelay(sockfd);
    set_tcp_quickack(sockfd);
}

static inline void send_reset_to_peer(int sockfd) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &(struct linger){.l_onoff = 1, .l_linger = 0}, sizeof(struct linger)) < 0) {
        LOGERR("[send_reset_to_peer] setsockopt(%d, SO_LINGER): %s", sockfd, my_strerror(errno));
    }
}

static inline int new_nonblock_sockfd(int family, int sktype) {
    int sockfd = socket(family, sktype, 0);
    if (sockfd < 0) {
        LOGERR("[new_nonblock_sockfd] socket(%s, %s): %s", family == AF_INET ? "AF_INET" : "AF_INET6", sktype == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM", my_strerror(errno));
        exit(errno);
    }
    set_non_block(sockfd);
    if (family == AF_INET6) set_ipv6_only(sockfd);
    set_reuse_addr(sockfd);
    return sockfd;
}

int new_tcp_listen_sockfd(int family, bool is_tproxy, bool is_reuse_port, bool is_tfo_accept) {
    int sockfd = new_nonblock_sockfd(family, SOCK_STREAM);
    if (is_tproxy) set_ip_transparent(family, sockfd);
    if (is_reuse_port) set_reuse_port(sockfd);
    if (is_tfo_accept) set_tfo_accept(sockfd);
    return sockfd;
}

int new_tcp_connect_sockfd(int family, uint8_t tcp_syncnt) {
    int sockfd = new_nonblock_sockfd(family, SOCK_STREAM);
    set_tcp_nodelay(sockfd);
    set_tcp_quickack(sockfd);
    if (tcp_syncnt) set_tcp_syncnt(sockfd, tcp_syncnt);
    return sockfd;
}

int new_udp_tprecv_sockfd(int family) {
    int sockfd = new_nonblock_sockfd(family, SOCK_DGRAM);
    set_ip_transparent(family, sockfd);
    set_recv_origdstaddr(family, sockfd);
    return sockfd;
}

int new_udp_tpsend_sockfd(int family) {
    int sockfd = new_nonblock_sockfd(family, SOCK_DGRAM);
    set_ip_transparent(family, sockfd);
    return sockfd;
}

int new_udp_normal_sockfd(int family) {
    return new_nonblock_sockfd(family, SOCK_DGRAM);
}

bool get_tcp_orig_dstaddr(int family, int sockfd, void *dstaddr, bool is_tproxy) {
    socklen_t addrlen = (family == AF_INET) ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
    if (is_tproxy) {
        if (getsockname(sockfd, dstaddr, &addrlen) < 0) {
            LOGERR("[get_tcp_orig_dstaddr] addr_family:%s, getsockname(%d): %s", (family == AF_INET) ? "inet" : "inet6", sockfd, my_strerror(errno));
            return false;
        }
    } else {
        if (family == AF_INET) {
            if (getsockopt(sockfd, IPPROTO_IP, SO_ORIGINAL_DST, dstaddr, &addrlen) < 0) {
                LOGERR("[get_tcp_orig_dstaddr] getsockopt(%d, SO_ORIGINAL_DST): %s", sockfd, my_strerror(errno));
                return false;
            }
        } else {
            if (getsockopt(sockfd, IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, dstaddr, &addrlen) < 0) {
                LOGERR("[get_tcp_orig_dstaddr] getsockopt(%d, IP6T_SO_ORIGINAL_DST): %s", sockfd, my_strerror(errno));
                return false;
            }
        }
    }
    return true;
}

bool get_udp_orig_dstaddr(int family, struct msghdr *msg, void *dstaddr) {
    if (family == AF_INET) {
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
                memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(skaddr4_t));
                return true;
            }
        }
    } else {
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
                memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(skaddr6_t));
                return true;
            }
        }
    }
    return false;
}

bool tcp_accept(int sockfd, int *conn_sockfd, void *from_skaddr) {
    *conn_sockfd = accept(sockfd, from_skaddr, from_skaddr ? &(socklen_t){sizeof(skaddr6_t)} : NULL);
    if (*conn_sockfd < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return false;
    if (*conn_sockfd >= 0) setup_accepted_sockfd(*conn_sockfd);
    return true;
}

bool tcp_connect(int sockfd, const void *skaddr, const void *data, size_t datalen, ssize_t *nsend) {
    socklen_t skaddrlen = ((skaddr4_t *)skaddr)->sin_family == AF_INET ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
    if (data && datalen && nsend) {
        if ((*nsend = sendto(sockfd, data, datalen, MSG_FASTOPEN, skaddr, skaddrlen)) < 0 && errno != EINPROGRESS) return false;
    } else {
        if (connect(sockfd, skaddr, skaddrlen) < 0 && errno != EINPROGRESS) return false;
    }
    return true;
}

bool tcp_recv_data(int sockfd, void *data, size_t datalen, size_t *nrecv) {
    ssize_t ret = recv(sockfd, data + *nrecv, datalen - *nrecv, 0);
    if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return false;
    if (ret > 0) *nrecv += ret;
    return true;
}

bool tcp_send_data(int sockfd, const void *data, size_t datalen, size_t *nsend) {
    ssize_t ret = send(sockfd, data + *nsend, datalen - *nsend, 0);
    if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return false;
    if (ret > 0) *nsend += ret;
    return true;
}

void tcp_close_by_rst(int sockfd) {
    send_reset_to_peer(sockfd);
    close(sockfd);
}
