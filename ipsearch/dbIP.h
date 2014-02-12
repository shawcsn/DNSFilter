#ifndef DBIP_H_INCLUDED
#define DBIP_H_INCLUDED

#include "dbUtility.h"

result_t InitIpTree(void);
/*
 * Usage:  initial the  IP blacklist datebase.
 * Inout:   @param  void
 * Output:  @return result_t
 *                  ------ R_SUCCESS, initial success
 *                  ------ R_FAILED,  initial failed
 */
result_t DestroyIpTree(void);
/*
 * Usage:  Destroy the blacklist datebase
 * Inout:   @param  void
 * Output:  @return result_t
 *                  ------ R_SUCCESS, free resource success
 *                  ------ R_FAILED,  free resource failed
 */
result_t SearchIpdata(unsigned int ip,unsigned char* control_flags,unsigned int *redip);
/*
 * Usage: For search IP in the blacklist datebase.
 * Input: @param  unsigned int ip ----- ip
 *        @param  unsigned char* control_flags ----- store the return value (control type)
 *        @param  unsigned int *redip ----- save the redirect IP
 * Output: @return result_t
 *                ----- R_FOUND,found the IP
 *                ----- R_NOTFOUND, not found.
 */
int UpdateIpdata(void* collection,size_t size,unsigned char tag);
/*
 * Usage: For update data(add,delete or renew) to blacklist datebase.
 * Input: @param  void* collection ----- record set (exclude set-header)
 * 	  @param  size_t size  ----- data size of records (bytes)
 *        @param  unsigned char tag ----- operation type(normal or fast)
 * Output: @return int
 *                 ------ count of records which update success
 */
result_t SaveIPToFile(void* collection,size_t size);
/*
 * Usage: Write the update data to file.
 * Input: @param  void* collection ----- record set (exclude set-header)
 * 	  @param  size_t size  ----- data size of records (bytes)
 * Output: @return result_t
 *                 ------ R_SUCCESS, save success
 *                 ------ R_FAILED, save failed
 */
#ifdef  DB_DEBUG
void PrintT(void);   /* for debug the DB, print the tree (后序遍历) */
#endif


#endif // DBIP_H_INCLUDED
