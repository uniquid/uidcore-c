/*
 * UID_dispatch.c
 *
 *  Created on: 27/oct/2016
 *      Author: M. Palumbi
 */

#ifndef __UID_DISPATCH_C
#define __UID_DISPATCH_C

#include <stdlib.h>
#include "UID_dispatch.h"

UID_user_callback UID_callbacks[UID_RPC_TABLE_SIZE] = {
    NULL,
    NULL
};

int UID_register_user_callback(int index, UID_user_callback callback)
{
    if (index < UID_RPC_RESERVED) return UID_DISPATCH_RESERVED;
    if (NULL != UID_callbacks[index]) return UID_DISPATCH_INUSE;
    UID_callbacks[index] = callback;
    return UID_DISPATCH_OK;
}

int UID_dispatch(int method, char *params, char *result, size_t size, UID_smart_contract smart_contract)
{
    if(0 == ((method & 0xff) & smart_contract[method >> 8])) return UID_DISPATCH_NOPERMISSION;
    if (NULL == UID_callbacks[method]) return UID_DISPATCH_NOTREGISTERED;
    UID_callbacks[method](params, result, size);
    return UID_DISPATCH_OK;
}

#endif //__UID_DISPATCH_C
