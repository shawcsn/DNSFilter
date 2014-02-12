#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include "dbIP.h"

#define LH 1
#define EH 0
#define RH -1

#define IP_VALID_YES	0
#define IP_VALID_NO	1

#define FALSE 0
#define TRUE 1

#pragma pack(push, 1)
typedef struct ipData
{
	unsigned int ipval;
	unsigned char ctrl_type:2,
		      valid_type:2,
		      reserve:4;
	unsigned int redirect_ip;
}ipData,*pData;
#pragma pack(pop)

typedef struct ipNode
{
	ipData data;
	int balance;
	struct ipNode *lchild, *rchild;
}ipNode, *ipTree;

static void R_Rotate(ipTree *T);
static void L_Rotate(ipTree *T);
static int InsertAVL(ipTree *T, pData data, int *taller);
static void LeftBalance(ipTree *T);
static void RightBalance(ipTree *T);
static void FreeTree(ipTree T);

ipTree root=NULL;
pthread_rwlock_t TreeLock;             //Lock the AVL Tree.

static void R_Rotate(ipTree *T)
{
	ipTree lpcur;
	lpcur=(*T)->lchild;
	(*T)->lchild=lpcur->rchild;
	lpcur->rchild=*T;
	(*T)=lpcur;
}
static void L_Rotate(ipTree *T)
{
	ipTree rpcur;
	rpcur=(*T)->rchild;
	(*T)->rchild=rpcur->lchild;
	rpcur->lchild=*T;
	(*T)=rpcur;
}
static int InsertAVL(ipTree *T, pData data, int *taller)
{
	if(!(*T))
	{
        	//Empty tree.
		(*T)=(ipTree)malloc(sizeof(ipNode));
		(*T)->data.ipval=data->ipval;
		(*T)->data.ctrl_type=data->ctrl_type;
		(*T)->data.valid_type=data->valid_type;
		(*T)->data.redirect_ip=data->redirect_ip;
		(*T)->lchild=NULL;
		(*T)->rchild=NULL;
		(*T)->balance=EH;
		*taller=TRUE;
	}else{
		if(data->ipval==(*T)->data.ipval)
		{
			(*T)->data.valid_type=data->valid_type;
			(*T)->data.ctrl_type=data->ctrl_type;
                        (*T)->data.redirect_ip=data->redirect_ip;
                	*taller=FALSE;
			return 0;
		}

		if(data->ipval < (*T)->data.ipval)
		{
                	if(!InsertAVL(&((*T)->lchild),data,taller))
				return 0;
			if(*taller)
				switch((*T)->balance){
				case LH:
					LeftBalance(T);
					*taller=FALSE;
					break;
				case EH:
					(*T)->balance=LH;
					*taller=TRUE;
					break;
				case RH:
					(*T)->balance=EH;
					*taller=FALSE;
					break;
				}
		}else{
                	if(!InsertAVL(&((*T)->rchild),data,taller))
				return 0;
			if(*taller)
				switch((*T)->balance){
				case LH:
					(*T)->balance=EH;
					*taller=FALSE;
					break;
				case EH:
					(*T)->balance=RH;
					*taller=TRUE;
					break;
				case RH:
					RightBalance(T);
					*taller=FALSE;
					break;
				}
		}
	}
	return 1;
}
static void LeftBalance(ipTree *T)
{
	ipTree lpcur,rd;
	lpcur=(*T)->lchild;
	switch(lpcur->balance)
	{
        case LH:
		(*T)->balance=EH;
		lpcur->balance=EH;
		R_Rotate(T);
		break;
	case RH:
		rd=lpcur->rchild;
		switch(rd->balance)
		{
                case LH:
			(*T)->balance=RH;
			lpcur->balance=EH;
			break;
		case EH:
			(*T)->balance=EH;
			lpcur->balance=EH;
			break;
		case RH:
			(*T)->balance=EH;
			lpcur->balance=LH;
			break;
		}
		rd->balance=EH;
		L_Rotate(&((*T)->lchild));
		R_Rotate(T);
	}
}
static void RightBalance(ipTree *T)
{
 	ipTree rpcur,ld;
	rpcur=(*T)->rchild;
	switch(rpcur->balance)
	{
        case RH:
		(*T)->balance=EH;
		rpcur->balance=EH;
		L_Rotate(T);
		break;
	case LH:
		ld=rpcur->lchild;
		switch(ld->balance)
		{
                case RH:
			(*T)->balance=LH;
			rpcur->balance=EH;
			break;
		case EH:
			(*T)->balance=EH;
			rpcur->balance=EH;
			break;
		case LH:
			(*T)->balance=EH;
			rpcur->balance=RH;
			break;
		}
		ld->balance=EH;
		R_Rotate(&((*T)->rchild));
		L_Rotate(T);
	}
}
static void FreeTree(ipTree T)
{
	if(T==NULL)
		return;
	if(T->lchild)
		FreeTree(T->lchild);
	if(T->rchild)
		FreeTree(T->rchild);
	free(T);
}
result_t InitIpTree(void)
{
        int fin;
	void *start;
	struct stat sb;
	//initial lock
	pthread_rwlock_init(&TreeLock, NULL);

	fin=open(IP_DATA_PATH,O_RDONLY);
	if(fin != -1)
	{
		fstat(fin,&sb);
		if(sb.st_size>0)
		{
			start=mmap(NULL,sb.st_size,PROT_READ,MAP_PRIVATE,fin,0);
			if(start== MAP_FAILED) /*判断是否映射成功*/
			{
				close(fin);
				return R_FAILED;
			}
			UpdateIpdata(start,sb.st_size,0);
			munmap(start,sb.st_size); /*解除映射*/
		}
		close(fin);
	}
	return R_SUCCESS;
}
result_t DestroyIpTree()
{
	pthread_rwlock_destroy(&TreeLock);
	FreeTree(root);
	return R_SUCCESS;
}
result_t SearchIpdata(unsigned int ip,unsigned char* control_flags,unsigned int *redip)
{
	result_t ret = R_NOTFOUND;
	ipTree pcur;
	pthread_rwlock_rdlock(&TreeLock);
	pcur=root;
	while(pcur)
	{
        if(pcur->data.ipval==ip)
		{
			if(pcur->data.valid_type==IP_VALID_YES)
			{
                *control_flags=pcur->data.ctrl_type;
				*redip=pcur->data.redirect_ip;
				ret = R_FOUND;
			}
			break;
		} else if(pcur->data.ipval<ip)
			pcur=pcur->rchild;
		else
			pcur=pcur->lchild;
	}
	pthread_rwlock_unlock(&TreeLock);
	if(ret == R_FOUND && *control_flags == CFLAG_REDIRECT && *redip == 0)
	{
		//指定默认重定向地址
		*redip = inet_addr(DEFAULT_REDI_IP);
	}
	return ret;
}
int UpdateIpdata(void* collection,size_t size,unsigned char tag)
{
	//'tag' have ignored
	size_t sum=0;
	void* start=collection;
	struct data_hdr *hdr;
	int count=0,flag=0,ret=0;
	ipData data;
	char ipbuff[16];

	while(sum<size)
	{
		hdr=(struct data_hdr *)start;
		start+=sizeof(*hdr);
		data.ctrl_type=hdr->control_type;
		data.valid_type=hdr->opcode_type;

		sum=sum + hdr->val_length + hdr->info_length + sizeof(*hdr);

		if(hdr->val_length == 0 || hdr->val_length >15)
		{
                	start=start + hdr->val_length + hdr->info_length;
			continue;
		}else{
			memcpy(ipbuff,start,hdr->val_length);
			ipbuff[hdr->val_length]='\0';
			start= start+hdr->val_length;
			data.ipval=inet_addr(ipbuff);
                }

		if(hdr->info_length >15)
		{
                	start=start + hdr->info_length;
			continue;
		}else if(hdr->info_length == 0){
			data.redirect_ip=0;
		}else{
			memcpy(ipbuff,start,hdr->info_length);
			ipbuff[hdr->info_length]='\0';
			start= start+hdr->info_length;
			data.redirect_ip=inet_addr(ipbuff);
                }

		pthread_rwlock_wrlock(&TreeLock);
		ret=InsertAVL(&root,&data,&flag);
		pthread_rwlock_unlock(&TreeLock);

		count++;
	}
	return count;
}
result_t SaveIPToFile(void* collection,size_t size)
{
        int fin;
	size_t sz=0;

	fin=open(IP_SAVE_PATH,O_WRONLY|O_CREAT|O_APPEND,666);
	sz=write(fin,collection,size);
	close(fin);

	return sz == size ? R_SUCCESS : R_FAILED;
}

#ifdef  DB_DEBUG
static void PrintTree(ipTree T)
{
	if(T==NULL)
		return;
	if(T->lchild)
		PrintTree(T->lchild);
	if(T->rchild)
		PrintTree(T->rchild);
	printf("----  %d  ----\n",T->data.ipval);
}
void PrintT()
{
	PrintTree(root);
}
#endif

