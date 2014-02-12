#ifndef LIBIPQ_H_INCLUDED
#define LIBIPQ_H_INCLUDED

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/netfilter_ipv4/ip_queue.h>

typedef unsigned long ipq_id_t;

struct ipq_handle
{
    int fd;
    struct sockaddr_nl local;
    struct sockaddr_nl peer;
};

struct ipq_handle *ipq_create_handle();

int ipq_destroy_handle(struct ipq_handle *h);

ssize_t ipq_read(const struct ipq_handle *h, unsigned char *buf, size_t len);

int ipq_set_mode(const struct ipq_handle *h, u_int8_t mode, size_t len);

ipq_packet_msg_t *ipq_get_packet(const unsigned char *buf);

int ipq_message_type(const unsigned char *buf);

int ipq_get_msgerr(const unsigned char *buf);

int ipq_set_verdict(const struct ipq_handle *h,
                    ipq_id_t id,
                    unsigned int verdict,
                    size_t data_len,
                    unsigned char *buf);

int ipq_ctl(const struct ipq_handle *h, int request, ...);
static ssize_t ipq_netlink_recvfrom(const struct ipq_handle *h,
                                    unsigned char *buf, size_t len);
char *ipq_errstr(void);


#endif // LIBIPQ_H_INCLUDED
