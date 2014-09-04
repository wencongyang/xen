/*
 * Copyright (C) 2014 FUJITSU LIMITED
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * Almost all codes are copied from iproute.
 *
 * colo-agent introduces a new qdisc colo, and needs some parameter.
 * tc only supports new qdisc without parameter, so we introduce
 * a new simple command to support this new qdisc.
 *
 * The licenses of iproute is GPLv2 or later.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#define TCA_BUF_MAX (64*1024)
#define NEXT_ARG()                                          \
    do {                                                    \
        argv++;                                             \
        if (--argc <= 0) {                                  \
            fprintf(stderr, "Command line is not complete." \
                    " Try option \"help\"\n");              \
            return -1;                                      \
        }                                                   \
    } while(0)

enum {
    TCA_COLO_UNSPEC,
    TCA_COLO_DEV_IDX,
    TCA_COLO_FLAGS,
    TCA_COLO_VM_IDX,
    __TCA_COLO_MAX,
};

struct colo_idx {
    uint32_t this_idx;
    uint32_t other_idx;
};

/* flags */
#define IS_PRIMARY   (1 << 0)


struct rtnl_handle
{
    int         fd;
    struct sockaddr_nl  local;
    struct sockaddr_nl  peer;
    __u32           seq;
};

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
    socklen_t addr_len;
    int sndbuf = 32768;
    int rcvbuf = 1024 * 1024;

    memset(rth, 0, sizeof(*rth));

    rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (rth->fd < 0) {
        perror("Cannot open netlink socket");
        return -1;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf,
                   sizeof(sndbuf)) < 0) {
        perror("SO_SNDBUF");
        return -1;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
                   sizeof(rcvbuf)) < 0) {
        perror("SO_RCVBUF");
        return -1;
    }

    memset(&rth->local, 0, sizeof(rth->local));
    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = subscriptions;
    if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
        perror("Cannot bind netlink socket");
        return -1;
    }

    addr_len = sizeof(rth->local);
    if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
        perror("Cannot getsockname");
        return -1;
    }
    if (addr_len != sizeof(rth->local)) {
        fprintf(stderr, "Wrong address length %d\n", addr_len);
        return -1;
    }
    if (rth->local.nl_family != AF_NETLINK) {
        fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
        return -1;
    }

    rth->seq = time(NULL);
    return 0;
}

static int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
              unsigned groups, struct nlmsghdr *answer)
{
    int status;
    unsigned seq;
    struct nlmsghdr *h;
    struct sockaddr_nl nladdr;
    struct iovec iov = {
        .iov_base = (void*) n,
        .iov_len = n->nlmsg_len
    };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    char   buf[16384];

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = peer;
    nladdr.nl_groups = groups;

    n->nlmsg_seq = seq = ++rtnl->seq;

    if (answer == NULL)
        n->nlmsg_flags |= NLM_F_ACK;

    status = sendmsg(rtnl->fd, &msg, 0);

    if (status < 0) {
        perror("Cannot talk to rtnetlink");
        return -1;
    }

    memset(buf,0,sizeof(buf));

    iov.iov_base = buf;

    while (1) {
        iov.iov_len = sizeof(buf);
        status = recvmsg(rtnl->fd, &msg, 0);

        if (status < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            fprintf(stderr, "netlink receive error %s (%d)\n",
                strerror(errno), errno);
            return -1;
        }
        if (status == 0) {
            fprintf(stderr, "EOF on netlink\n");
            return -1;
        }
        if (msg.msg_namelen != sizeof(nladdr)) {
            fprintf(stderr, "sender address length == %d\n", msg.msg_namelen);
            exit(1);
        }
        for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
            int len = h->nlmsg_len;
            int l = len - sizeof(*h);

            if (l < 0 || len>status) {
                if (msg.msg_flags & MSG_TRUNC) {
                    fprintf(stderr, "Truncated message\n");
                    return -1;
                }
                fprintf(stderr, "!!!malformed message: len=%d\n", len);
                exit(1);
            }

            if (nladdr.nl_pid != peer ||
                h->nlmsg_pid != rtnl->local.nl_pid ||
                h->nlmsg_seq != seq) {
                /* Don't forget to skip that message. */
                status -= NLMSG_ALIGN(len);
                h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                continue;
            }

            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                if (l < sizeof(struct nlmsgerr)) {
                    fprintf(stderr, "ERROR truncated\n");
                } else {
                    if (!err->error) {
                        if (answer)
                            memcpy(answer, h, h->nlmsg_len);
                        return 0;
                    }

                    fprintf(stderr, "RTNETLINK answers: %s\n", strerror(-err->error));
                    errno = -err->error;
                }
                return -1;
            }
            if (answer) {
                memcpy(answer, h, h->nlmsg_len);
                return 0;
            }

            fprintf(stderr, "Unexpected reply!!!\n");

            status -= NLMSG_ALIGN(len);
            h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
        }
        if (msg.msg_flags & MSG_TRUNC) {
            fprintf(stderr, "Message truncated\n");
            continue;
        }
        if (status) {
            fprintf(stderr, "!!!Remnant of size %d\n", status);
            exit(1);
        }
    }
}

static void rtnl_close(struct rtnl_handle *rth)
{
    if (rth->fd >= 0) {
        close(rth->fd);
        rth->fd = -1;
    }
}

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
              int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n",
                maxlen);
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

static void duparg(const char *key, const char *arg)
{
    fprintf(stderr, "Error: duplicate \"%s\": \"%s\" is the second value.\n",
            key, arg);
    exit(1);
}

static void invarg(const char *msg, const char *arg)
{
    fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n", arg, msg);
    exit(1);
}

static int usage(void)
{
    fprintf(stderr, "Usage: tc qdisc [ add | del | replace | change ] dev STRING\n");
    fprintf(stderr, "       [ handle QHANDLE ] [ root | parent CLASSID ]\n");
    fprintf(stderr, "       QDISC_KIND [ dev STRING ]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Where:\n");
    fprintf(stderr, "QDISC_KIND := { primary | secondary. }\n");
    return -1;
}

struct rtnl_handle rth;

static int get_qdisc_handle(__u32 *h, const char *str)
{
    __u32 maj;
    char *p;

    maj = TC_H_UNSPEC;
    if (strcmp(str, "none") == 0)
        goto ok;
    maj = strtoul(str, &p, 16);
    if (p == str)
        return -1;
    maj <<= 16;
    if (*p != ':' && *p!=0)
        return -1;
ok:
    *h = maj;
    return 0;
}

static int get_tc_classid(__u32 *h, const char *str)
{
    __u32 maj, min;
    char *p;

    maj = TC_H_ROOT;
    if (strcmp(str, "root") == 0)
        goto ok;
    maj = TC_H_UNSPEC;
    if (strcmp(str, "none") == 0)
        goto ok;
    maj = strtoul(str, &p, 16);
    if (p == str) {
        maj = 0;
        if (*p != ':')
            return -1;
    }
    if (*p == ':') {
        if (maj >= (1<<16))
            return -1;
        maj <<= 16;
        str = p+1;
        min = strtoul(str, &p, 16);
        if (*p != 0)
            return -1;
        if (min >= (1<<16))
            return -1;
        maj |= min;
    } else if (*p != 0)
        return -1;

ok:
    *h = maj;
    return 0;
}

static uint32_t get_idx(const char *name)
{
    uint32_t idx;

    idx = if_nametoindex(name);
    if (!idx)
        fprintf(stderr, "Cannot find device \"%s\"\n", name);

    return idx;
}

static int parse_opt(int argc, char **argv, struct nlmsghdr *n, int cmd, int this_idx)
{
    struct colo_idx idx;
    struct rtattr *tail;
    int is_primary, is_secondary;
    uint32_t flags = 0;
    uint32_t vmidx = 0;
    char *p;

    if (cmd != RTM_NEWQDISC)
        return 0;

    is_primary = 0;
    is_secondary = 0;
    memset(&idx, 0, sizeof(idx));

    while (argc > 0) {
        if (strcmp(*argv, "dev") ==0) {
            NEXT_ARG();
            if (idx.other_idx)
                duparg(*argv, "dev");

            idx.other_idx = get_idx(*argv);
            if (!idx.other_idx)
                return -1;

            idx.this_idx = this_idx;
            if (idx.this_idx == idx.other_idx) {
                fprintf(stderr, "Cannot use the same device\n");
                return -1;
            }
        } else if (strcmp(*argv, "primary") == 0) {
            if (is_secondary) {
                fprintf(stderr, "\"primary\" conflicts with \"secondary\"\n");
                return -1;
            }

            is_primary = 1;
        } else if (strcmp(*argv, "secondary") == 0) {
            if (is_secondary) {
                fprintf(stderr, "\"secondary\" conflicts with \"primary\"\n");
                return -1;
            }

            is_secondary = 1;
        } else if (strcmp(*argv, "vmid") == 0) {
            NEXT_ARG();
            if (vmidx)
                duparg(*argv, "vmid");

            vmidx = strtoul(*argv, &p, 10);
            if (*p != '\0' || !vmidx) {
                fprintf(stderr, "invalid vmid value %s\n", *argv);
                return -1;
            }
        } else {
            fprintf(stderr, "unsupported option \"%s\"\n", *argv);
            return -1;
        }
        argc--;
        argv++;
    }

    if (!idx.other_idx) {
        fprintf(stderr, "missing option dev\n");
        return -1;
    }

    if (!is_primary && !is_secondary) {
        fprintf(stderr, "missing option primary or secondary\n");
        return -1;
    }

    if (!vmidx) {
        fprintf(stderr, "missing option vmidx\n");
        return -1;
    }

    if (is_primary)
        flags |= IS_PRIMARY;

    tail = NLMSG_TAIL(n);
    addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
    addattr_l(n, 1024, TCA_COLO_DEV_IDX, &idx, sizeof(idx));
    addattr_l(n, 1024, TCA_COLO_FLAGS, &flags, sizeof(flags));
    addattr_l(n, 1024, TCA_COLO_VM_IDX, &vmidx, sizeof(vmidx));
    tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
    return 0;
}

static int tc_qdisc_modify(int cmd, unsigned flags, int argc, char **argv)
{
    struct {
        struct nlmsghdr n;
        struct tcmsg t;
        char buff[TCA_BUF_MAX];
    } req;
    char k[16];
    uint32_t handle = 0, idx = 0;

    memset(&req, 0, sizeof(req));
    memset(k, 0, sizeof(k));

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST|flags;
    req.n.nlmsg_type = cmd;
    req.t.tcm_family = AF_UNSPEC;

    while (argc > 0) {
        if (strcmp(*argv, "dev") == 0) {
            NEXT_ARG();
            if (req.t.tcm_ifindex)
                duparg("dev", *argv);

            idx = get_idx(*argv);
            if (!idx)
                return -1;
            req.t.tcm_ifindex = idx;
        } else if (strcmp(*argv, "handle") == 0) {
            NEXT_ARG();
            if (req.t.tcm_handle)
                duparg("handle", *argv);
            if (get_qdisc_handle(&handle, *argv))
                invarg(*argv, "invalid qdisc ID");
            req.t.tcm_handle = handle;
        } else if (strcmp(*argv, "root") == 0) {
            if (req.t.tcm_parent) {
                fprintf(stderr, "Error: \"root\" is duplicate parent ID\n");
                return -1;
            }
            req.t.tcm_parent = TC_H_ROOT;
        } else if (strcmp(*argv, "parent") == 0) {
            NEXT_ARG();
            if (req.t.tcm_parent)
                duparg("parent", *argv);
            if (get_tc_classid(&handle, *argv))
                invarg(*argv, "invalid parent ID");
            req.t.tcm_parent = handle;
        } else if (strcmp(*argv, "colo") == 0) {
            strncpy(k, *argv, sizeof(k) - 1);
            argc--;
            argv++;
            break;
        } else if (strcmp(*argv, "help") == 0){
            usage();
            return 0;
        } else {
            fprintf(stderr, "unsupported qdisc %s\n", *argv);
            return -1;
        }
        argc--;
        argv++;
    }

    if (!k[0]) {
        fprintf(stderr, "no qdisc is specified\n");
        return -1;
    }

    addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);
    if (parse_opt(argc, argv, &req.n, cmd, idx))
        return -1;

    if (rtnl_talk(&rth, &req.n, 0, 0, NULL) < 0)
        return -1;

    return 0;
}

static int matches(const char *cmd, const char *pattern)
{
    int len = strlen(cmd);
    if (len > strlen(pattern))
        return -1;
    return memcmp(pattern, cmd, len);
}

static int do_qdisc(int argc, char *argv[])
{
    if (matches(*argv, "add") == 0)
        return tc_qdisc_modify(RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, argc-1, argv+1);
    if (matches(*argv, "change") == 0)
        return tc_qdisc_modify(RTM_NEWQDISC, 0, argc-1, argv+1);
    if (matches(*argv, "replace") == 0)
        return tc_qdisc_modify(RTM_NEWQDISC, NLM_F_CREATE|NLM_F_REPLACE, argc-1, argv+1);
    if (matches(*argv, "link") == 0)
        return tc_qdisc_modify(RTM_NEWQDISC, NLM_F_REPLACE, argc-1, argv+1);
    if (matches(*argv, "delete") == 0)
        return tc_qdisc_modify(RTM_DELQDISC, 0,  argc-1, argv+1);

    fprintf(stderr, "Command \"%s\" is unknown, try \"tc qdisc help\".\n", *argv);
    return -1;
}

int main(int argc, char *argv[])
{
    int ret;

    if (rtnl_open(&rth, 0) < 0) {
        fprintf(stderr, "Cannot open rtnetlink\n");
        exit(1);
    }

    if (matches(argv[1], "qdisc")) {
        usage();
        exit(1);
    }

    argc -= 2;
    argv += 2;

    if (argc < 1) {
        usage();
        exit(1);
    }

    ret = do_qdisc(argc, argv);

    rtnl_close(&rth);

    if (ret)
        return 1;

    return 0;
}
