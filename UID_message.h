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

typedef struct {
    BTC_Address peerid;
    BTC_Address myid;
} UID_client_channel_ctx;

typedef struct {
    BTC_Address peerid;
    BTC_Address myid;
} UID_server_channel_ctx;

#define UID_MESSAGE_OK 0
#define UID_OPEN_CHANNEL_NOT_FOUND 1

// client side functions
int UID_open_channel(char *dest_name, UID_client_channel_ctx *channel_ctx);
int UID_format_request(uint8_t *buffer, size_t *size, UID_client_channel_ctx *channel_ctx, int method, char *params, int *id);
int UID_parse_result(uint8_t *buffer, size_t size, UID_client_channel_ctx *channel_ctx, char *res, int id);
int UID_close_channel(UID_client_channel_ctx *channel_ctx);

// provider side functions
int UID_accept_channel(UID_server_channel_ctx *channel_ctx, int8_t *in_msg, size_t in_size, int8_t *first_msg, size_t *out_size);
int UID_perform_request(uint8_t *buffer, size_t size, uint8_t response, size_t *rsize, UID_server_channel_ctx *channel_ctx);
int UID_close_server_channel(UID_server_channel_ctx *channel_ctx);


#endif //__UID_MESSAGE_H
