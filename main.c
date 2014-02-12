#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "packet/queueip.h"
#include "packet/packet_filter.h"
#include "domainsearch/dbDomain.h"
#include "domainsearch/domainUpdate.h"
#include "ipsearch/dbIP.h"
#include "ipsearch/ipUpdate.h"
#include <sys/timeb.h>
#include <sys/stat.h>
#include <unistd.h>
struct ipq_handle *h = NULL;
FILE *fp_config;
FILE *fp_log;
pthread_t ptd_ip_update, ptd_domain_update;

static void sig_int(int signo)
{
    ipq_destroy_handle(h);
    printf("Exit: %s\n", ipq_errstr());
    exit(0);
}

int main(void)
{
    InitializeSearchTree();
    InitIpTree();
    InitShm();
    IPInitShm();
    pthread_create(&ptd_ip_update,NULL,(void *)IPUpdateCreate,NULL);
    pthread_create(&ptd_domain_update,NULL,(void *)UpdateCreate,NULL);

    unsigned char buf[1024];
    /* creat handle*/
    h = ipq_create_handle(0, PF_INET);
    if (h == NULL)
    {
        printf("%s\n", ipq_errstr());
        return 0;
    }
    printf("ipq_creat_handle success!\n");
    /*set mode*/
    unsigned char mode = IPQ_COPY_PACKET;
    int range = sizeof(buf);
    int ret = ipq_set_mode(h, mode, range);
    printf("ipq_set_mode: send bytes =%d, range=%d\n", ret, range);

    /*register signal handler*/
    signal(SIGINT, sig_int);

    /*read packet from kernel*/
    long int status;
    struct nlmsghdr *nlh;
    ipq_packet_msg_t *ipq_packet;

    struct tm *save_time;
    struct timeb tp;
    ftime(&tp);
    time_t previous=tp.time;
    struct tm *current_time;
    char file_name[64];
    char file[64];
    int i=1,have=0;
    struct stat buffer;
    int flag=sizeof(struct nlmsghdr);
    printf("system start success!\n");
    while (1)
    {
        ftime(&tp);
        status = ipq_read(h, buf, sizeof(buf));
        if (status > flag && status<10000)    //有数据包收到
        {
            if(i==1)       //第一次收到数据
            {
                previous=tp.time;    //previous得到初值
                current_time=localtime(&tp.time);
                sprintf(file_name,"%s%s%d%02d%02d %02d%02d%02d%s",LOG_FILE_PATH,"DomainCtrl",current_time->tm_year+1900,current_time->tm_mon+1,current_time->tm_mday,current_time->tm_hour,current_time->tm_min,current_time->tm_sec,".log"); //创建第一个日志文件
                fp_log=fopen(file_name,"a+");
                if(fp_log==NULL)
                {
                    perror("Create File Failed\n");
                    exit(-1);
                }
                i=0;
            }
            nlh = (struct nlmsghdr *)buf;
            ipq_packet = ipq_get_packet(buf);   //得到数据包
            packet_handle(ipq_packet,fp_log);   //处理数据包
        }
        if((tp.time-previous)%30!=0)
        {
            have=1;
        }
        if(tp.time-previous==30 && i==0 && have==1)  //经过30秒 第二次创建日志文件满足条件
        {
            save_time=localtime(&previous);
            sprintf(file_name,"%s%s%d%02d%02d %02d%02d%02d%s",LOG_FILE_PATH,"DomainCtrl",save_time->tm_year+1900,save_time->tm_mon+1,save_time->tm_mday,save_time->tm_hour,save_time->tm_min,save_time->tm_sec,".log");  //得到已经写好的日志的文件名
            fclose(fp_log);  //关闭已经写好的日志文件
            stat(file_name,&buffer);
            if(buffer.st_size==0)
            {
                remove(file_name); //删除空日志文件
                i=1;
            }
            else           //日志文件不为空
            {
                sprintf(file,"DomainCtrl%4d%02d%02d %02d%02d%02d.log",save_time->tm_year+1900,save_time->tm_mon+1,save_time->tm_mday,save_time->tm_hour,save_time->tm_min,save_time->tm_sec);         //得到日志文件的文件名
                fp_config = fopen("/opt/Data/Logs/config","w");  //打开只写文件，若文件存在则文件长度清为0，即该文件内容会消失。若文件不存在则建立该文件。
                fprintf(fp_config,"%d\n%s",1,file);   //将非空日志文件名写入config文件
                fclose(fp_config);

                previous=tp.time;
                current_time=localtime(&tp.time);       //创建新的日志文件
                sprintf(file_name,"%s%s%d%02d%02d %02d%02d%02d%s",LOG_FILE_PATH,"DomainCtrl",current_time->tm_year+1900,current_time->tm_mon+1,current_time->tm_mday,current_time->tm_hour,current_time->tm_min,current_time->tm_sec,".log"); //定义文件名
                fp_log=fopen(file_name,"a+");
                if(fp_log==NULL)
                {
                    perror("Create File Failed\n");
                    exit(-1);
                }

            }
            have=0;
        }
    }
    return 0;
}
