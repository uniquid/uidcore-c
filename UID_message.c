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
#include <stdio.h>
#include <time.h>

#include "yajl/yajl_gen.h"
#include "yajl/yajl_tree.h"
#include "UID_message.h"
#include "UID_bchainBTC.h"

int UID_open_channel(char *dest_name, UID_client_channel_ctx *channel_ctx)
{
    UID_ClientProfile *provider;

	if (NULL == (provider = UID_matchProvider(dest_name))) return UID_MSG_NOT_FOUND;
    strncpy(channel_ctx->myid, provider->serviceUserAddress, sizeof(channel_ctx->myid));

    return UID_MSG_OK;
}

int UID_format_request(uint8_t *buffer, size_t *size, UID_client_channel_ctx *channel_ctx, int method, char *params, int *id)
{
    yajl_gen g;
    const uint8_t *json;
    size_t sz;
    int ret;

    *id = time(NULL);

    g = yajl_gen_alloc(NULL);
    if (NULL == g) return UID_MSG_GEN_ALLOC_FAIL;

/*
    yajl_gen_map_open(g);
        yajl_gen_string(g, (uint8_t *)"sender", 6);
        yajl_gen_string(g, (uint8_t *)channel_ctx->myid, strlen(channel_ctx->myid));
        yajl_gen_string(g, (uint8_t *)"body", 4);
        yajl_gen_map_open(g);
            yajl_gen_string(g, (uint8_t *)"method", 6);
            yajl_gen_integer(g, method);
            yajl_gen_string(g, (uint8_t *)"params", 6);
            yajl_gen_string(g, (uint8_t *)params, strlen(params));
            yajl_gen_string(g, (uint8_t *)"id", 2);
            yajl_gen_integer(g, *id);
        yajl_gen_map_close(g);
    yajl_gen_map_close(g);

    yajl_gen_get_buf(g, &json, &sz); //get the buffer
    //if(sz > size) return
    strncpy((char *)buffer, (char *)json, *size);
*/
    ret = UID_MSG_GEN_FAIL;
    if (yajl_gen_status_ok != yajl_gen_string(g, (uint8_t *)params, strlen(params))) goto clean;
    if (yajl_gen_status_ok != yajl_gen_get_buf(g, &json, &sz)) goto clean; //get the buffer
    sz = snprintf((char *)buffer, *size, "{\"sender\":\"%s\",\"body\":{\"method\":%d,\"params\":%s,\"id\":%d}}", channel_ctx->myid, method, json, *id);
    ret = UID_MSG_SMALL_BUFFER;
    if (sz >= *size) goto clean;
    *size = sz;

    ret = UID_MSG_OK;
clean:
    yajl_gen_clear(g);
    yajl_gen_free(g);

    return ret;
}

int UID_accept_channel(uint8_t *in_msg, size_t in_size, UID_server_channel_ctx *channel_ctx, uint8_t *first_msg, size_t *out_size)
{
    yajl_val node, v;
    char *s;
    UID_SecurityProfile *contract;
    int ret;

    // parse message
	node = yajl_tree_parse((char *)in_msg, NULL, 0);
    if (node == NULL) return UID_MSG_JPARSE_ERROR;

    ret = UID_MSG_JPARSE_ERROR;
    const char * sender[] = { "sender", (const char *) 0 };
    v = yajl_tree_get(node, sender, yajl_t_string);
    if (v == NULL) goto clean_return;
    s =  YAJL_GET_STRING(v);

    ret = UID_MSG_NO_CONTRACT;
    contract = UID_matchContract(s);
    if (NULL == contract) goto clean_return;
    memcpy(&(channel_ctx->contract), contract, sizeof(channel_ctx->contract));

    ret = UID_MSG_SMALL_BUFFER;
    if (in_size > *out_size) goto clean_return;
    memcpy(first_msg, in_msg, in_size);

    ret = UID_MSG_OK;
clean_return:
    yajl_tree_free(node);
    return ret;
}