#ifndef IPUPDATE_H_INCLUDED
#define IPUPDATE_H_INCLUDED

#include <pthread.h>
#include "dbUtility.h"

extern pthread_t update_thread;
#define SIGUPDATE   10

result_t IPInitShm(void);
/*
 * Usage: initial Share memory, attach to share memory.
 * @param   void  --- null
 * @return  result_t
             ---- R_SUCCESS: initial success;
             ---- R_FAILED: initial failed
 */
result_t IPDetShm(void);
/*
 * Usage: detach from share memory
 * @param   void  --- null
 * @return  result_t
             ---- R_SUCCESS: operate success;
             ---- R_FAILED: operate failed
 */

void* IPUpdateCreate(void *arg);
/*
 * Usage: process update of url (used for thread)
 * @param   void *arg --- nothing
 * @return  void* --- nothing
 */

#endif // IPUPDATE_H_INCLUDED
