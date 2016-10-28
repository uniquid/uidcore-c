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
#include "UID_dispatch.h"

int UID_open_channel(char *dest_name, UID_client_channel_ctx *channel_ctx)
{
    UID_ClientProfile *provider;

	if (NULL == (provider = UID_matchProvider(dest_name))) return UID_MSG_NOT_FOUND;
    strncpy(channel_ctx->myid, provider->serviceUserAddress, sizeof(channel_ctx->myid));
    strncpy(channel_ctx->peerid, provider->serviceProviderAddress, sizeof(channel_ctx->peerid));

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
    *size = sz + 1;  // add the end of string

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

    ret = UID_MSG_NO_CONTRACT;  // We dont have a contract. we dont send any answer...
    contract = UID_matchContract(s);
    if (NULL == contract) goto clean_return;
    memcpy(&(channel_ctx->contract), contract, sizeof(channel_ctx->contract));

    ret = UID_MSG_SMALL_BUFFER;
    if (in_size > *out_size) goto clean_return;
    memcpy(first_msg, in_msg, in_size);
    *out_size = in_size;

    ret = UID_MSG_OK;
clean_return:
    yajl_tree_free(node);
    return ret;
}


//  {"sender":"my3CohS9f57yCqNy4yAPbBRqLaAAJ9oqXV","body":{"method":33,"params":"{\"pippa\":\"lapeppa\"}","id":1477550301}}

int UID_perform_request(uint8_t *buffer, size_t size, uint8_t *response, size_t *rsize, UID_server_channel_ctx *channel_ctx)
{
(void)size;
    yajl_val node, v;
    int ret;
    yajl_gen g = NULL;

    // parse message
	node = yajl_tree_parse((char *)buffer, NULL, 0);
    if (node == NULL) return UID_MSG_JPARSE_ERROR;

    ret = UID_MSG_JPARSE_ERROR;
    const char * sender[] = { "sender", (const char *) 0 };
    v = yajl_tree_get(node, sender, yajl_t_string);
    if (v == NULL) goto clean_return;
    char *s =  YAJL_GET_STRING(v);
    ret = UID_MSG_INVALID_SENDER;
    if (strcmp(s,channel_ctx->contract.serviceUserAddress)) goto clean_return;

    ret = UID_MSG_JPARSE_ERROR;
    const char * _method[] = { "body", "method", (const char *) 0 };
    v = yajl_tree_get(node, _method, yajl_t_number);
    if (v == NULL) goto clean_return;
    int method =  YAJL_GET_INTEGER(v);

    ret = UID_MSG_JPARSE_ERROR;
    const char * _id[] = { "body", "id", (const char *) 0 };
    v = yajl_tree_get(node, _id, yajl_t_number);
    if (v == NULL) goto clean_return;
    int id =  YAJL_GET_INTEGER(v);

    ret = UID_MSG_JPARSE_ERROR;
    const char * _params[] = { "body", "params", (const char *) 0 };
    v = yajl_tree_get(node, _params, yajl_t_string);
    if (v == NULL) goto clean_return;
    char *params =  YAJL_GET_STRING(v);

    char result[1024] = {0}; // must find a better way to allocate the buffer!!!
    int error = UID_dispatch(method, params, result, sizeof(result), channel_ctx->contract.profile);

    // build the response
    ret = UID_MSG_GEN_ALLOC_FAIL;
    g = yajl_gen_alloc(NULL);
    if (NULL == g) goto clean_return;

    size_t sz;
    const uint8_t *json;
    ret = UID_MSG_GEN_FAIL;
    if (yajl_gen_status_ok != yajl_gen_string(g, (uint8_t *)result, strlen(result))) goto clean_return;
    if (yajl_gen_status_ok != yajl_gen_get_buf(g, &json, &sz)) goto clean_return; //get the buffer
    sz = snprintf((char *)response, *rsize, "{\"sender\":\"%s\",\"body\":{\"result\":%s,\"error\":%d,\"id\":%d}}", channel_ctx->contract.serviceProviderAddress, json, error, id);
    ret = UID_MSG_SMALL_BUFFER;
    if (sz >= *rsize) goto clean_return;
    *rsize = sz + 1;  // add the end of string

    ret = UID_MSG_OK;
clean_return:
    if (NULL != node) yajl_tree_free(node);
    if (NULL != g) yajl_gen_free(g);
    return ret;
}
