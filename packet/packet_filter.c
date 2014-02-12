#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "packet_filter.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "queueip.h"
#include "../domainsearch/dbDomain.h"
#include "../ipsearch/dbIP.h"
#include "../domainsearch/dbUtility.h"

#define ETH_HDRLEN 14
#define MAX_DOMAIN_LEN 1024
#define NF_ACCEPT 	1
#define NF_DROP  	0


#define LOG_FILE_PATH  "/opt/Data/Logs/"


#define MAX_LOG_ITEM 10000
extern struct ipq_handle *h;
int sec,min,hour,day,mon,year;
int ret=0;
static int i=1;
long internal;
struct tm *current_time,*previous_time;
static u_int32_t log_item_count = 0;


clock_t start;

char *get_current_time()
{
    char *dispose_time = (char *)malloc(sizeof(char )* 16);
    struct tm *current_time;
    time_t t;
    time(&t);
    current_time=localtime(&t);
    sprintf(dispose_time,"%02d:%02d:%02d",current_time->tm_hour,current_time->tm_min,current_time->tm_sec);
    return dispose_time;
}

void control_log(char *dispose_time,char control_type, char *request_ip, char *request_domain, char *rip, unsigned int ip,FILE *fp_log)
{
    char file_name[64];
    if(ip == 0)
        fprintf(fp_log,"%s %d %s %s %s\n",dispose_time,control_type,request_ip,request_domain,rip);
    else
    {
        char addr[16];
        inet_ntop(AF_INET,&ip,addr,16);
        fprintf(fp_log,"%s %d %s %s %s %s\n",dispose_time,control_type,request_ip,addr,request_domain,rip);
    }
    fflush(fp_log);
    free(dispose_time);
    free(request_domain);

}


char *get_query_domain_name(const u_char *packet_content)
{
    struct ip *iphdr = (struct ip*)(packet_content);
    char *domain_name = (char *)malloc(256 * sizeof(char));
    char sub_domain_name[64];
    char *dns_content = (char *)(packet_content+8+12+iphdr->ip_hl*4);
    memset(domain_name,0,256);
    memset(sub_domain_name,0,64);
    u_int8_t len;
    while ((len=(u_int8_t)(*dns_content)) != 0)
    {
        dns_content++;
        strncpy(sub_domain_name,dns_content,len);
        strcat(domain_name,sub_domain_name);
        strcat(domain_name,".");
        memset(sub_domain_name,0,64);
        dns_content += len;
    }
    char *p =domain_name;
    while (*p)
        p++;
    *(--p)='\0';
    return domain_name;
}

struct in_addr *get_response_ip(const u_char *packet_content, u_int16_t *answer_count)
{

    u_int16_t iphdr_len = ((struct ip*)(packet_content))->ip_hl*4;
    struct dns_header *dns_hdr = (struct dns_header *)(packet_content+8+iphdr_len);
    u_int16_t count = ntohs(dns_hdr->dns_answer_count);
    *answer_count = count;
    struct in_addr *ip_addr = (struct in_addr *)malloc(count*sizeof(struct in_addr));
    memset((char *)ip_addr,0,count*sizeof(struct in_addr));
    u_char *dns_content = (u_char *)(packet_content+8+12+iphdr_len);
    u_int8_t len = 0;
    while ((len=(u_int8_t)(*dns_content)) != 0)
    {
        dns_content = len + dns_content +1;
    }
    dns_content += 5;
    while (count > 0)
    {
        dns_content += 2;
        if (ntohs(*(u_int16_t *)(dns_content))== 1)
        {
            dns_content += 10;
            memcpy(&(ip_addr[count-1].s_addr),dns_content,4);
            dns_content +=4;
        }
        else
        {
            dns_content += 8;
            dns_content += ntohs(*((u_int16_t *)(dns_content)));
            dns_content += 2;
        }
        count--;
    }
    return ip_addr;

}

u_int16_t checksum(const u_char *packet_content,u_int32_t caplen)
{
    u_int8_t fill_packet = 0;
    struct ip *ip_hdr = (struct ip *)(packet_content);
    struct udphdr *udp_hrd = (struct udphdr *)(packet_content+ip_hdr->ip_hl*4);
    udp_hrd->check = 0;
    u_int16_t check_size = caplen;
    if (check_size % 2 == 1)
    {
        check_size += 1;
        fill_packet = 1;
    }
    u_char *check_content = (u_char *)malloc(12+check_size);
    memcpy(check_content,&ip_hdr->ip_src,4);
    memcpy(check_content+4,&ip_hdr->ip_dst,4);
    memset(check_content+8,0,1);
    memset(check_content+9,0x11,1);
    memcpy(check_content+10,&udp_hrd->len,2);
    memcpy(check_content+12,packet_content+ip_hdr->ip_hl*4,check_size);
    if (fill_packet)
        memset(check_content+check_size+11,0,1);
    u_int16_t *buffer = (u_int16_t *)check_content;
    u_int32_t cksum  = 0;
    u_int16_t size = check_size+12;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= 2;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    free(check_content);
    return (u_int16_t)(~cksum);
}

void rebuild_redirection_packet(ipq_packet_msg_t *ipq_packet, u_int32_t rip, unsigned int ips,FILE *fp_log)
{
    u_int16_t iphdr_len = ((struct ip*)(ipq_packet->payload))->ip_hl*4;
    u_char *dns_content = (u_char *)(ipq_packet->payload+iphdr_len+8+12);
    struct udphdr *udp_hdr = (struct udphdr *)(ipq_packet->payload+iphdr_len);
    struct dns_header *dns_hrd = (struct dns_header *)(ipq_packet->payload+8+iphdr_len);
    u_int8_t len;
    u_int16_t query_type;
    u_int8_t answer_count = ntohs(dns_hrd->dns_answer_count);
    u_int32_t ip_addr;
    while ((len=(u_int8_t)(*dns_content)) != 0)
    {
        dns_content = dns_content + len + 1;
    }
    dns_content += 5;
    while (answer_count > 0)
    {
        dns_content += 2;
        query_type = ntohs(*((u_int16_t *)(dns_content)));
        if (query_type == 1)
        {
            //	ip_addr = inet_addr("123.127.134.10");
            dns_content += 10;
            memcpy(dns_content,&rip,4);
            dns_content += 4;
        }
        else
        {
            dns_content += 8;
            dns_content += ntohs(*((u_int16_t *)(dns_content)));
            dns_content += 2;
        }
        answer_count--;
    }
    u_int16_t rechecksum = checksum(ipq_packet->payload, ntohs(udp_hdr->len));
    memcpy(&udp_hdr->check,&rechecksum,2);
    ret= ipq_set_verdict(h, ipq_packet->packet_id, NF_ACCEPT,ipq_packet->data_len,ipq_packet->payload );

    char addr[16];
    inet_ntop(AF_INET,&rip,addr,16);
	control_log(get_current_time(),1,inet_ntoa(( (struct ip*)(ipq_packet->payload))->ip_dst),get_query_domain_name(ipq_packet->payload),addr,ips,fp_log);
}

void rebuild_cheat_packet(ipq_packet_msg_t *ipq_packet,unsigned int ips,FILE *fp_log)
{
    struct ip *iphdr = (struct ip*)(ipq_packet->payload);
    u_int16_t iphdr_len = iphdr->ip_hl*4;
    u_char *dns_content = (u_char *)(ipq_packet->payload+iphdr_len+8+12);
    u_char *content_head = dns_content;
    u_int8_t len;
    while ((len=(u_int8_t)(*dns_content)) != 0)
    {
        dns_content = dns_content + len + 1;
    }
    u_int8_t query_len = (u_int8_t *)(dns_content-content_head+5);
    u_int32_t orgin_len = query_len  + iphdr_len + 8 + 12 ;
    u_int32_t packet_len = orgin_len + 75;
    iphdr->ip_len = htons(packet_len );
    iphdr->ip_sum = 0;
    u_int16_t *buffer = (u_int16_t *)(ipq_packet->payload);
    u_int32_t cksum  = 0;
    u_int16_t size = iphdr_len;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= 2;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    iphdr->ip_sum = (u_int16_t)(~cksum);
    char author_server[75] =
    {
        0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x07, 0x08, 0x00, 0x40, 0x01, 0x61, 0x0C, 0x72,
        0x6F, 0x6F, 0x74, 0x2D, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6E, 0x65, 0x74,
        0x00, 0x05, 0x6E, 0x73, 0x74, 0x6C, 0x64, 0x0C, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67,
        0x6E, 0x2D, 0x67, 0x72, 0x73, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x77, 0xDD, 0x95, 0x61, 0x00,
        0x00, 0x07, 0x08, 0x00, 0x00, 0x03, 0x84, 0x00, 0x09, 0x3A, 0x80, 0x00, 0x01, 0x51, 0x80,
    };
    u_char *forge_packet_content = (u_char *)malloc(packet_len);
    memcpy(forge_packet_content,ipq_packet->payload,orgin_len);
    memcpy(forge_packet_content+orgin_len,author_server,75);
    u_int16_t *udp_len = (u_int16_t *)(forge_packet_content+iphdr_len+4);
    *udp_len = htons(8+12+query_len+75);
    u_int16_t *dns_flag = (u_int16_t *)(forge_packet_content+iphdr_len+8+2);
    *dns_flag = htons(0x8183);
    char question_count[8] = {0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00};
    memcpy(forge_packet_content+iphdr_len+8+4,question_count,8);
    u_int16_t rechecksum = checksum(forge_packet_content, 8+12+query_len+75);
    struct udphdr *udp_hdr = (struct udphdr *)(forge_packet_content+iphdr_len);
    memcpy(&udp_hdr->check,&rechecksum,2);
    memcpy(ipq_packet->payload,forge_packet_content,packet_len);
    ipq_packet->data_len=packet_len;
    ret= ipq_set_verdict(h, ipq_packet->packet_id, NF_ACCEPT,ipq_packet->data_len,ipq_packet->payload );
    free(forge_packet_content);
    control_log(get_current_time(),2,inet_ntoa(iphdr->ip_dst),get_query_domain_name(ipq_packet->payload),"\0",ips,fp_log);
}

void dispose_packet(ipq_packet_msg_t *ipq_packet,const unsigned char flags,const unsigned int rip,const unsigned int ip,FILE *fp_log)
{
    switch (flags)
    {
    case 1:
        rebuild_redirection_packet(ipq_packet,rip,ip,fp_log);
        break;
    case 2:
        rebuild_cheat_packet(ipq_packet,ip,fp_log);
        break;
    case 0:
        ret= ipq_set_verdict(h, ipq_packet->packet_id,  NF_DROP,ipq_packet->data_len,ipq_packet->payload );
        control_log(get_current_time(),0,inet_ntoa(((struct ip*)(ipq_packet->payload))->ip_dst),get_query_domain_name(ipq_packet->payload),"\0",ip,fp_log);
        break;
    default:
        ret= ipq_set_verdict(h, ipq_packet->packet_id, NF_ACCEPT,ipq_packet->data_len,ipq_packet->payload );
    }
}

void packet_handle(ipq_packet_msg_t *ipq_packet,FILE *fp_log)
{
   //long L1,L2,L3,L4;
  // struct timeval tv;

//    printf("indev=%s, datalen=%d, packet_id=%x\n", ipq_packet->indev_name,  ipq_packet->data_len, ipq_packet->packet_id);
     unsigned char flags;
    char *info = NULL;
    unsigned int rip = 0;

    struct ip *ip_protocol = (struct ip*)(ipq_packet->payload);
    struct dns_header *dns_hdr =(struct dns_header*)(ipq_packet->payload+ip_protocol->ip_hl*4+8);
    if (ntohs(dns_hdr->dns_flag)&0x8000 )
    {
        char *domain_name = get_query_domain_name(ipq_packet->payload);
//        printf("Response Name\t:%s\t\n",domain_name);
       // if (strcmp(domain_name,"www.baidu.com") == 0)

//gettimeofday(&tv, NULL);      //(2)
//L1 = tv.tv_sec*1000*1000 + tv.tv_usec;
        if (SearchDomainName(domain_name,&flags,&info)==R_FOUND	)
        {
             if(flags==1)
                rip = inet_addr(info);
            //rip = inet_addr("123.127.134.10");
            dispose_packet(ipq_packet,flags,rip,0,fp_log);
            //ret = ipq_set_verdict(h, ipq_packet->packet_id, NF_ACCEPT,ipq_packet->data_len,ipq_packet->payload );
            free(domain_name);
        }
        else
        {
            control_log(get_current_time(),3,inet_ntoa(ip_protocol->ip_dst),domain_name,"\0",0,fp_log);
          //  free(domain_name);
            u_int16_t answer_count = 0;
            struct in_addr *ip_addr = get_response_ip(ipq_packet->payload,&answer_count);
            while (answer_count > 0)
            {
//                printf("IP Adress : %s\t\n",inet_ntoa(ip_addr[answer_count-1].s_addr));
               // if (strcmp(inet_ntoa(ip_addr[answer_count-1].s_addr),"202.102.144.56") == 0)
//gettimeofday(&tv, NULL);      //(2)
//L3 = tv.tv_sec*1000*1000 + tv.tv_usec;
               if(SearchIpdata(ip_addr[answer_count-1].s_addr, &flags, &rip)==R_FOUND)
                {
//gettimeofday(&tv, NULL);
//L4 = tv.tv_sec*1000*1000+tv.tv_usec;
//printf("time %ld\n", L4-L3);
//                    printf("ip find: type=%d\n",flags);
                     //if(flags==1)
                    //rip = inet_addr(info);
                  //  dispose_packet(packet_content,cap_len,flags,rip,ip_addr[answer_count-1].s_addr);
                    dispose_packet(ipq_packet,flags,rip,ip_addr[answer_count-1].s_addr,fp_log);
                    free(ip_addr);
                    break;
                }
                else
                    control_log(get_current_time(),3,inet_ntoa(ip_protocol->ip_dst),get_query_domain_name(ipq_packet->payload),"\0",ip_addr[answer_count-1].s_addr,fp_log);
                answer_count--;
            }
            if (answer_count == 0)
            {
                free(ip_addr);
                ret = ipq_set_verdict(h, ipq_packet->packet_id, NF_ACCEPT,ipq_packet->data_len,ipq_packet->payload );
            }
        }
    }
    else
        ret = ipq_set_verdict(h, ipq_packet->packet_id, NF_ACCEPT,ipq_packet->data_len,ipq_packet->payload );
}



