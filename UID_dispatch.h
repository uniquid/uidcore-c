/*
 * UID_dispatch.h
 *
 *  Created on: 27/oct/2016
 *      Author: M. Palumbi
 */

#ifndef __UID_DISPATCH_H
#define __UID_DISPATCH_H

#include "UID_bchainBTC.h"

#define UID_RPC_TABLE_SIZE (40*8)
#define UID_RPC_RESERVED 32

#define UID_DISPATCH_OK 0
//#define UID_DISPATCH_NOCONTRACT 1
#define UID_DISPATCH_NOPERMISSION 2
#define UID_DISPATCH_NOTREGISTERED 3
#define UID_DISPATCH_RESERVED 4
#define UID_DISPATCH_INUSE 5

typedef void (*UID_user_callback)(char *param, char *result, size_t size);

int UID_register_user_callback(int index, UID_user_callback callback);

int UID_dispatch(int method, char *params, char *result, size_t size, UID_smart_contract smart_contract);

#endif //__UID_DISPATCH_H
