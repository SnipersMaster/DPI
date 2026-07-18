/*
 * dpi_secure_bootstrap.c
 *
 * Reference skeleton for a Linux DPI engine's security-critical startup path.
 * This is NOT a full DPI engine — it demonstrates the four protocols from the
 * checklist that matter most before you write a single dissector:
 *
 *   1. Open the raw capture socket while still root
 *   2. Drop privileges immediately after (setgroups -> setgid -> setuid)
 *   3. Restrict syscalls with seccomp-bpf before touching any packet data
 *   4. Parse packets with strict, explicit bounds checks
 *
 * Build (requires dev packages, e.g. `apt install libseccomp-dev libcap-dev`):
 *   gcc -O2 -Wall -Wextra -o dpi_bootstrap dpi_secure_bootstrap.c -lseccomp -lcap
 *
 * Run (needs CAP_NET_RAW, not full root — see setcap note at bottom):
 *   sudo setcap cap_net_raw,cap_net_admin=eip ./dpi_bootstrap
 *   ./dpi_bootstrap eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <seccomp.h>

#define UNPRIV_USER   "dpi-svc"     /* dedicated, shell-less service account */
#define SNAPLEN       65535
#define ETH_HDR_LEN   14

/* ---------------------------------------------------------------------
 * 1. Open the raw capture socket while still root.
 *    Bind to a specific interface, not the whole machine, and keep this
 *    the ONLY privileged operation in the program.
 * --------------------------------------------------------------------- */
static int open_capture_socket(const char *ifname) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket(AF_PACKET) - do you have CAP_NET_RAW?");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(sock);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

/* ---------------------------------------------------------------------
 * 2. Drop privileges immediately after the socket is open.
 *    Order matters: setgroups -> setgid -> setuid. Reversing this order
 *    leaves the process able to reclaim root via a lingering group.
 * --------------------------------------------------------------------- */
static int drop_privileges(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "drop_privileges: user '%s' not found. "
                        "Create it: useradd -r -s /usr/sbin/nologin %s\n",
                username, username);
        return -1;
    }

    if (setgroups(0, NULL) != 0) { perror("setgroups"); return -1; }
    if (setgid(pw->pw_gid) != 0) { perror("setgid");     return -1; }
    if (setuid(pw->pw_uid) != 0) { perror("setuid");     return -1; }

    /* Verify the drop actually worked. Never assume; check. */
    if (setuid(0) == 0) {
        fprintf(stderr, "FATAL: privilege drop failed, still able to regain root\n");
        return -1;
    }

    fprintf(stderr, "privileges dropped: now running as uid=%d gid=%d\n",
            getuid(), getgid());
    return 0;
}

/* ---------------------------------------------------------------------
 * 3. Restrict syscalls with seccomp-bpf before any packet parsing runs.
 *    Allowlist only what the capture+parse loop actually needs. Extend
 *    this list deliberately, not by trial-and-error against denials.
 * --------------------------------------------------------------------- */
static int install_seccomp_filter(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        return -1;
    }

    int allowed[] = {
        SCMP_SYS(read), SCMP_SYS(recvfrom), SCMP_SYS(recvmsg),
        SCMP_SYS(write), SCMP_SYS(sendto),
        SCMP_SYS(close), SCMP_SYS(exit), SCMP_SYS(exit_group),
        SCMP_SYS(brk), SCMP_SYS(mmap), SCMP_SYS(munmap),
        SCMP_SYS(rt_sigreturn), SCMP_SYS(nanosleep),
        SCMP_SYS(clock_gettime), SCMP_SYS(gettimeofday),
    };

    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed[i], 0) < 0) {
            fprintf(stderr, "seccomp_rule_add failed for syscall index %zu\n", i);
            seccomp_release(ctx);
            return -1;
        }
    }

    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "seccomp_load failed\n");
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    fprintf(stderr, "seccomp filter active: any other syscall now kills the process\n");
    return 0;
}

/* ---------------------------------------------------------------------
 * 4. Parse with strict, explicit bounds checks.
 *    This is the pattern to repeat for every protocol dissector: never
 *    trust a length field until it's validated against the buffer you
 *    actually have.
 * --------------------------------------------------------------------- */
static void parse_ethernet_frame(const unsigned char *buf, ssize_t len) {
    if (len < ETH_HDR_LEN) {
        /* Too short to even contain an Ethernet header. Drop, don't guess. */
        return;
    }

    uint16_t ethertype = ntohs(*(const uint16_t *)(buf + 12));
    const unsigned char *payload = buf + ETH_HDR_LEN;
    ssize_t payload_len = len - ETH_HDR_LEN;

    if (ethertype == ETH_P_IP) {
        if (payload_len < 20) return;          /* min IPv4 header */
        uint8_t ihl = (payload[0] & 0x0F) * 4;
        if (ihl < 20 || ihl > payload_len) return;  /* malformed IHL: drop */
        /* Hand off (payload + ihl, payload_len - ihl) to the next dissector.
         * Every subsequent dissector applies this same discipline:
         * check length before reading, reject rather than clamp-and-continue. */
    }
    /* else: unrecognized ethertype - drop or hand to a generic dissector,
     * but never index into buf using an unvalidated offset. */
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }

    int sock = open_capture_socket(argv[1]);
    if (sock < 0) return 1;

    if (drop_privileges(UNPRIV_USER) != 0) {
        close(sock);
        return 1;
    }

    if (install_seccomp_filter() != 0) {
        close(sock);
        return 1;
    }

    unsigned char buf[SNAPLEN];
    for (;;) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }
        parse_ethernet_frame(buf, n);
    }

    close(sock);
    return 0;
}
