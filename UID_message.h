/*
 * UID_message.h
 *
 *  Created on: 24/oct/2016
 *      Author: M. Palumbi
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
} UID_server_channel_ctx;

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

// client side functions
int UID_openChannel(char *destMachine, UID_ClientChannelCtx *ctx);
int UID_format_request(uint8_t *buffer, size_t *size, UID_ClientChannelCtx *ctx, int method, char *params, int *id);
int UID_parse_result(uint8_t *buffer, size_t size, UID_ClientChannelCtx *ctx, char *res, size_t rsize, int id);
int UID_close_channel(UID_ClientChannelCtx *ctx);

// provider side functions
int UID_accept_channel(uint8_t *in_msg, size_t in_size, UID_server_channel_ctx *channel_ctx, uint8_t *first_msg, size_t *out_size);
int UID_perform_request(uint8_t *buffer, size_t size, uint8_t *response, size_t *rsize, UID_server_channel_ctx *channel_ctx);
int UID_close_server_channel(UID_server_channel_ctx *channel_ctx);


#endif //__UID_MESSAGE_H
