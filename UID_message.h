/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

 /**
 * @file   UID_message.h
 *
 * @date   24/oct/2016
 * @author M. Palumbi
 */

#ifndef __UID_MESSAGE_H
#define __UID_MESSAGE_H

#include <stdlib.h>
#include <stdint.h>
#include "UID_globals.h"
#include "UID_bchainBTC.h"

#define UID_MSG_TWINDOW 60000

typedef struct {
    UID_ClientProfile contract;
} UID_ClientChannelCtx;

typedef struct {
    UID_SecurityProfile contract;
} UID_ServerChannelCtx;

// user side functions
int UID_createChannel(char *destMachine, UID_ClientChannelCtx *ctx);
int UID_formatReqMsg(UID_Bip32Path *path, int method, char *params, uint8_t *msg, size_t *size, int64_t *sID);
int UID_parseRespMsg(uint8_t *msg, size_t size, char *sender, size_t ssize, int *error, char *result, size_t rsize, int64_t *sID);
int UID_closeChannel(UID_ClientChannelCtx *ctx);

// provider side functions
int UID_accept_channel(uint8_t *in_msg, size_t in_size, UID_ServerChannelCtx *channel_ctx, uint8_t *first_msg, size_t *out_size);
int UID_parseReqMsg(uint8_t *msg, size_t size, int *method, char *params, size_t psize, int64_t *sID);
int UID_formatRespMsg(UID_Bip32Path *path, char *result, int error, int64_t sID, uint8_t *msg, size_t *size);
int UID_closeServerChannel(UID_ServerChannelCtx *ctx);


#endif //__UID_MESSAGE_H
