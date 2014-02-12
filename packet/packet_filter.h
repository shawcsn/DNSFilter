#ifndef PACKET_FILTER_H_INCLUDED
#define PACKET_FILTER_H_INCLUDED

#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <stdio.h>
#include "queueip.h"

struct dns_header
{
    u_int16_t dns_id;
    u_int16_t dns_flag;
    u_int16_t dns_quest_count;
    u_int16_t dns_answer_count;
    u_int16_t dns_author_count;
    u_int16_t dns_addtion_count;

};

void packet_handle( ipq_packet_msg_t *ipq_packet,FILE *fp_log);
//extern void dns_domain_name_packet_callback( struct timeval ts, u_char *packet_content);
void initial_control_log(char flag);
#endif // PACKET_FILTER_H_INCLUDED
