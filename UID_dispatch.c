/*
 * UID_dispatch.c
 *
 *  Created on: 27/oct/2016
 *      Author: M. Palumbi
 */

#ifndef __UID_DISPATCH_C
#define __UID_DISPATCH_C

#include <stdlib.h>
#include <stdio.h>
#include "UID_dispatch.h"

static void UID_echo(char *param, char *result, size_t size)
{
	snprintf(result, size, "UID_echo: <%s>", param);
}

UID_SystemFuntion UID_systemFunctions[UID_RPC_RESERVED] = {
    UID_echo,
    NULL
};


/**
 * checks the contract for execution permission
 * @param method method to check for permission
 * @param smart_contract the contract
 */
int UID_checkPermission(int method, UID_smart_contract smart_contract)
{
    if(0 != ((1 << (method & 0x07)) & smart_contract[method >> 3])) {
        return 1;
    }
    else return 0;
}

int UID_performRequest(int method, char *params, char *result, size_t size)
{
    if(UID_RPC_RESERVED <= method) return UID_DISPATCH_NOTEXISTENT;
    if (NULL == UID_systemFunctions[method]) return UID_DISPATCH_NOTEXISTENT;
    UID_systemFunctions[method](params, result, size);
    return UID_DISPATCH_OK;
}

#endif //__UID_DISPATCH_C
