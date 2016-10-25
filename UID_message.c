/*
 * UID_message.c
 *
 *  Created on: 25/oct/2016
 *      Author: M. Palumbi
 */






/*
 * DESCRIPTION
 * Functions related to the RPC messages
 *
 */

#include <string.h>

#include "UID_message.h"
#include "UID_bchainBTC.h"

int UID_open_channel(char *dest_name, UID_client_channel_ctx *channel_ctx)
{
    UID_ClientProfile *provider;

	if (NULL == (provider = UID_matchProvider(dest_name))) return UID_OPEN_CHANNEL_NOT_FOUND;
    strncpy(channel_ctx->myid, provider->serviceUserAddress, sizeof(channel_ctx->myid));

    return UID_MESSAGE_OK;
}
