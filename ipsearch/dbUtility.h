#ifndef DBUTILITY_H_INCLUDED
#define DBUTILITY_H_INCLUDED

typedef int result_t;                 /* Function return type */

#define R_SUCCESS			0	/* operation success */
#define R_FAILED			1	/* operation failed */
#define R_FOUND				2	/* data have found */
#define R_INVALID                       3       /* data is deleting (when search in Cache used) */
#define R_NOTFOUND			4	/* data not found */

#define DATA_TYPE_DOMAIN 0                      /* data type (DOMAIN data) */
#define DATA_TYPE_IP	 1                      /* data type (IP data) */
#define DATA_TYPE_URL    2                      /* data type (URL data) */

#define UPDATE_NORMAL	 0                      /* update type (normal way to update) */
#define UPDATE_QUICK	 1                      /* update type (quick way to update) */

#define OPCODE_ADD	0                       /* operate type (add to DB) */
#define OPCODE_DELETE   1                       /* operate type (delete from DB) */

#define CFLAG_DROP 	0                       /* control type of data (drop) */
#define CFLAG_REDIRECT  1                       /* control type of data (redirect) */
#define CFLAG_CHEAT	2                       /* control type of data (cheat) */

#pragma pack(push,1)
/*
** header of a set of update records.(include: update type, data type, and  all records size <bytes> )
*/
struct record_set_hdr
{
	unsigned char update_type:2,
	              data_type:2,
	              reserve:4;
	unsigned int recd_size;
};
/*
** header of one record.(include: operate type, control type, data size <bytes>
**                                and  addition data size <bytes> )
*/
struct data_hdr
{
	unsigned char control_type:2,
		      opcode_type:2,
		      reserve:4;
	unsigned short  val_length;    /* size of data (domain or IP  or URL) */
	unsigned char	info_length;   /* size of addition data (redirect IP) */
};
#pragma pack(pop)

#define KEY_PATH "/opt/Data/IPData"
#define SHARE_SIZE  1024*1024
#define  SHARE_MEM_KEY  13
#define  SEM_SEND_KEY   14
#define  SEM_RECV_KEY   15

#define DEFAULT_REDI_IP  "123.127.134.10"

//#define DOMAIN_DATA_PATH "/opt/Data/init_domain.db"
//#define DOMAIN_SAVE_PATH "/opt/Data/save_domain.db"
#define IP_DATA_PATH "/opt/Data/IPData/ip.db"
#define IP_SAVE_PATH "/opt/Data/IPData/ip.db"
//#define URL_DATA_PATH "/opt/Data/init_url.db"
//#define URL_SAVE_PATH "/opt/Data/save_url.db"

#define PROG_ERROR_LOG "/opt/Data/Logs/ErrorLog.txt"
#define PROG_UPDATE_LOG "/opt/Data/Logs/UpdateLog.txt"
#define DATA_CTRL_LOG "/opt/Data/Logs/DataCtrlLog.txt"


#endif // DBUTILITY_H_INCLUDED
