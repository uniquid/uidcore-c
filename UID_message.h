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

typedef struct {
    BTC_Address peerid;
    BTC_Address myid;
} UID_ClientChannelCtx;

typedef struct {
    UID_SecurityProfile contract;
} UID_ServerChannelCtx;

#define UID_MSG_OK 0
#define UID_MSG_NOT_FOUND 1
#define UID_MSG_GEN_ALLOC_FAIL 2
#define UID_MSG_GEN_FAIL 3
#define UID_MSG_SMALL_BUFFER 4
#define UID_MSG_JPARSE_ERROR 5
#define UID_MSG_NO_CONTRACT 6
#define UID_MSG_INVALID_SENDER 7
#define UID_MSG_ID_MISMATCH 8
#define UID_MSG_RPC_ERROR 0x100

// user side functions
int UID_createChannel(char *destMachine, UID_ClientChannelCtx *ctx);
int UID_formatReqMsg(char *sender, int method, char *params, uint8_t *msg, size_t *size, int64_t *sID);
int UID_parseRespMsg(uint8_t *msg, size_t size, char *sender, size_t ssize, int *error, char *result, size_t rsize, int64_t *sID);
int UID_closeChannel(UID_ClientChannelCtx *ctx);

// provider side functions
int UID_accept_channel(uint8_t *in_msg, size_t in_size, UID_ServerChannelCtx *channel_ctx, uint8_t *first_msg, size_t *out_size);
int UID_parseReqMsg(uint8_t *msg, size_t size, char *sender, size_t ssize, int *method, char *params, size_t psize, int64_t *sID);
int UID_formatRespMsg(char *sender, char *result, int error, int64_t sID, uint8_t *msg, size_t *size);
int UID_closeServerChannel(UID_ServerChannelCtx *ctx);


#endif //__UID_MESSAGE_H
